"""Tests for signed, hash-chained attestations (verifiable receipts)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentbrake.server import attest, security, store
from agentbrake.server import main as server_main

SDK = "test-sdk"
APPROVER = "test-approver"
SIGNING_KEY = b"test-signing-key"
SDK_HEADERS = {"X-SDK-Secret": SDK}
APPROVER_HEADERS = {"X-Approver-Secret": APPROVER}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(store, "DEFAULT_DB_PATH", db_path)
    monkeypatch.setattr(security, "SDK_SECRET", SDK)
    monkeypatch.setattr(security, "APPROVER_SECRET", APPROVER)
    monkeypatch.setattr(attest, "SIGNING_KEY", SIGNING_KEY)
    store.init_db(db_path)
    return TestClient(server_main.app)


def _payload(run_id: str = "run-1", reason: str = "ESCALATION",
             tool: str = "delete_db", agent_id: str | None = None) -> dict:
    ctx: dict = {
        "tool": tool,
        "total_cost_usd": 0.07,
        "run_state": {
            "run_id": run_id,
            "calls": [{"name": "search", "args": {"q": "x"}}],
        },
    }
    if agent_id:
        ctx["agent_id"] = agent_id
    return {"run_id": run_id, "reason": reason, "context": ctx}


def _create(client: TestClient, **kw) -> str:
    r = client.post("/interrupts", json=_payload(**kw), headers=SDK_HEADERS)
    assert r.status_code == 200
    return r.json()["interrupt_id"]


def _decide(client: TestClient, iid: str, decision: str = "approve"):
    return client.post(
        f"/interrupts/{iid}/decide", json={"decision": decision}, headers=APPROVER_HEADERS
    )


def _db(client: TestClient) -> Path:
    return store.DEFAULT_DB_PATH


# --- Attestation is created on decision -----------------------------------

def test_decision_creates_attestation(client: TestClient) -> None:
    iid = _create(client, agent_id="agent-7")
    assert _decide(client, iid, "approve").status_code == 200

    resp = client.get(f"/attestations/{iid}")
    assert resp.status_code == 200
    body = resp.json()
    att = body["attestation"]

    assert att["seq"] == 1
    assert att["interrupt_id"] == iid
    assert att["run_id"] == "run-1"
    assert att["agent_id"] == "agent-7"
    assert att["decision"] == "approve"
    assert att["reason"] == "escalation"
    assert att["tool"] == "delete_db"
    assert att["tool_args_digest"].startswith("sha256:")
    assert att["info_digest"].startswith("sha256:")
    assert att["info_summary"]["num_calls"] == 1
    assert att["pending_seconds"] >= 0.0
    assert att["prev_hash"] == attest.GENESIS_HASH
    assert body["signature_valid"] is True


def test_no_attestation_before_decision(client: TestClient) -> None:
    iid = _create(client)
    assert client.get(f"/attestations/{iid}").status_code == 404


def test_kill_is_attested(client: TestClient) -> None:
    iid = _create(client)
    _decide(client, iid, "kill")
    att = client.get(f"/attestations/{iid}").json()["attestation"]
    assert att["decision"] == "kill"


def test_second_decision_does_not_create_a_second_receipt(client: TestClient) -> None:
    iid = _create(client)
    _decide(client, iid, "approve")
    again = _decide(client, iid, "kill")  # already decided — idempotent, no change
    assert again.status_code == 200
    assert again.json()["status"] == "approved"
    assert client.get("/attestations").json()["count"] == 1


# --- Signature verifies / tampering breaks it -----------------------------

def test_signature_verifies(client: TestClient) -> None:
    iid = _create(client)
    _decide(client, iid)
    rec = store.get_attestation(iid)
    assert attest.verify_signature(rec["attestation_json"], rec["signature"]) is True


def test_tampering_breaks_signature(client: TestClient) -> None:
    iid = _create(client)
    _decide(client, iid, "approve")
    rec = store.get_attestation(iid)

    # Flip the decision in the signed body; the old signature must no longer verify.
    tampered = rec["attestation_json"].replace('"decision":"approve"', '"decision":"kill"')
    assert tampered != rec["attestation_json"]
    assert attest.verify_signature(tampered, rec["signature"]) is False


def test_wrong_key_does_not_verify(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    iid = _create(client)
    _decide(client, iid)
    rec = store.get_attestation(iid)
    assert attest.verify_signature(rec["attestation_json"], rec["signature"], key=b"other") is False


# --- Hash chain links correctly -------------------------------------------

def test_chain_links_correctly(client: TestClient) -> None:
    ids = [_create(client, run_id=f"r{i}", tool=f"t{i}") for i in range(3)]
    for iid in ids:
        _decide(client, iid)

    body = client.get("/attestations").json()
    assert body["count"] == 3
    assert body["verified"] is True
    assert body["error"] is None

    chain = body["chain"]
    assert [c["seq"] for c in chain] == [1, 2, 3]
    assert chain[0]["prev_hash"] == attest.GENESIS_HASH
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]
    assert chain[2]["prev_hash"] == chain[1]["entry_hash"]
    assert all(c["signature_valid"] for c in chain)


def test_verify_endpoint_reports_ok(client: TestClient) -> None:
    for _ in range(2):
        _decide(client, _create(client))
    assert client.get("/attestations/verify").json() == {
        "ok": True,
        "count": 2,
        "error": None,
    }


def test_empty_chain_verifies(client: TestClient) -> None:
    assert client.get("/attestations/verify").json() == {
        "ok": True,
        "count": 0,
        "error": None,
    }


# --- Chain verification detects deletion / alteration ---------------------

def test_chain_detects_deleted_link(client: TestClient) -> None:
    ids = [_create(client, run_id=f"r{i}") for i in range(3)]
    for iid in ids:
        _decide(client, iid)

    conn = sqlite3.connect(_db(client))
    conn.execute("DELETE FROM attestations WHERE seq = 2")  # remove the middle link
    conn.commit()
    conn.close()

    ok, error = attest.verify_chain(store.get_attestation_chain())
    assert ok is False
    assert "non-consecutive" in error

    assert client.get("/attestations/verify").json()["ok"] is False


def test_chain_detects_altered_link(client: TestClient) -> None:
    ids = [_create(client) for _ in range(2)]
    for iid in ids:
        _decide(client, iid, "approve")

    # Rewrite the stored body of seq 1 without re-signing (attacker has no key).
    conn = sqlite3.connect(_db(client))
    row = conn.execute("SELECT attestation FROM attestations WHERE seq = 1").fetchone()
    altered = row[0].replace('"decision":"approve"', '"decision":"kill"')
    assert altered != row[0]
    conn.execute("UPDATE attestations SET attestation = ? WHERE seq = 1", (altered,))
    conn.commit()
    conn.close()

    ok, error = attest.verify_chain(store.get_attestation_chain())
    assert ok is False
    assert "signature" in error and "seq=1" in error

    assert client.get("/attestations/verify").json()["ok"] is False


def test_chain_detects_relinked_prev_hash(client: TestClient) -> None:
    """Even if an attacker rewrites a prev_hash column, the signed body's
    prev_hash no longer matches — the link is detected as broken."""
    for _ in range(2):
        _decide(client, _create(client))

    conn = sqlite3.connect(_db(client))
    conn.execute("UPDATE attestations SET prev_hash = ? WHERE seq = 2", ("deadbeef" * 8,))
    conn.commit()
    conn.close()

    # The signature still covers the real prev_hash, so verification fails on
    # the entry-hash recomputation rather than passing silently.
    ok, error = attest.verify_chain(store.get_attestation_chain())
    assert ok is False


# --- Pure-unit checks of the primitives -----------------------------------

def test_sign_verify_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attest, "SIGNING_KEY", b"k1")
    body = attest.canonical_json({"seq": 1, "a": "b"})
    sig = attest.sign(body)
    assert attest.verify_signature(body, sig) is True
    assert attest.verify_signature(body + "x", sig) is False
    assert attest.verify_signature(body, sig, key=b"k2") is False


def test_tool_call_digest_is_deterministic_and_order_independent() -> None:
    ctx_a = {"tool": "t", "run_state": {"calls": [{"name": "s", "args": {"a": 1, "b": 2}}]}}
    ctx_b = {"tool": "t", "run_state": {"calls": [{"name": "s", "args": {"b": 2, "a": 1}}]}}
    assert attest.tool_call_digest(ctx_a) == attest.tool_call_digest(ctx_b)
    assert attest.tool_call_digest(ctx_a).startswith("sha256:")
