"""Delegation receipts: every delegation decision leaves a verifiable trace.

Grant, acceptance, rejection and out-of-scope blocks are minted into the same
hash chain as flow blocks — one ledger per run, one export, one verifier. The
receipts embed the full signed token, so the export deep-check re-verifies the
delegations themselves, not just the receipts about them.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, DelegationError, delegation, receipts, signing
from agentbrake import export as export_mod
from agentbrake import report as report_mod
from agentbrake.server import attest

SIGNER = signing.Ed25519Signer.from_seed(b"\x0b" * 32)
PUBLIC_KEYS = {SIGNER.key_id: SIGNER.public_key_hex()}
INTENT = "Refund order #4521 for jane@corp.com"


@pytest.fixture(autouse=True)
def _fixed_signer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(attest, "SIGNER", SIGNER)


@pytest.fixture(autouse=True)
def _isolate_default_run():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return f"{name}-ok"


def _token(**overrides) -> delegation.DelegationToken:
    kwargs = dict(
        delegator="support-agent",
        delegatee="finance-agent",
        intent=INTENT,
        tools=["lookup_order", "issue_refund"],
        ttl_seconds=300,
    )
    kwargs.update(overrides)
    return delegation.grant(**kwargs)


def _kinds(rows: list) -> list:
    return [r["attestation"].get("kind") for r in rows]


# --- receipts are minted at each decision point --------------------------------

def test_accept_is_receipted_and_chain_verifies():
    token = _token()
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund"], budget_usd=10.0, delegation=token
    ) as r:
        dispatch("lookup_order", {})
    rows = r.flow_receipts()
    assert _kinds(rows) == ["delegation_accept"]
    att = rows[0]["attestation"]
    assert att["decision"] == "accept"
    assert att["reason"] == "delegation"
    assert att["agent_id"] == "finance-agent"
    assert att["delegation"]["token_digest"] == token.digest
    assert att["delegation"]["links"] == token.links  # full proof embedded
    ok, error = r.verify_receipts()
    assert ok, error


def test_out_of_scope_block_is_receipted_and_attached():
    token = _token()
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund", "send_email"],
        budget_usd=10.0,
        delegation=token,
    ) as r:
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {})
    rows = r.flow_receipts()
    assert _kinds(rows) == ["delegation_accept", "delegation_block"]
    block = rows[1]["attestation"]
    assert block["tool"] == "send_email"
    assert block["delegation"]["violation"] == "out_of_scope"
    # The interrupt carries the receipt, like flow blocks do.
    assert ei.value.context["receipt"]["entry_hash"] == rows[1]["entry_hash"]
    ok, error = r.verify_receipts()
    assert ok, error


def test_rejected_token_is_receipted_before_the_run_dies(tmp_path: Path):
    ledger_path = tmp_path / "receipts.jsonl"
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = _token(issued_at=past, ttl_seconds=5)
    with pytest.raises(DelegationError):
        agentbrake.run(
            allowed_tools=["lookup_order"],
            delegation=expired,
            receipts_path=str(ledger_path),
        )
    rows = receipts.JsonlLedger(str(ledger_path)).all()
    assert _kinds(rows) == ["delegation_reject"]
    assert "error" in rows[0]["attestation"]["delegation"]
    ok, error = receipts.verify_chain(rows, public_keys=PUBLIC_KEYS)
    assert ok, error


def test_grant_inside_a_run_is_receipted():
    with agentbrake.run(allowed_tools=["lookup_order"], budget_usd=10.0) as r:
        _token()  # granted while this run is active
    rows = r.flow_receipts()
    assert _kinds(rows) == ["delegation_grant"]
    assert rows[0]["attestation"]["decision"] == "grant"


def test_grant_outside_any_run_is_unreceipted_but_works():
    token = _token()  # no active run, no ledger param
    assert delegation.verify(token)["ok"] is True


def test_grant_with_explicit_ledger():
    ledger = receipts.InMemoryLedger()
    _token(ledger=ledger)
    assert _kinds(ledger.all()) == ["delegation_grant"]


# --- export deep verification ----------------------------------------------------

def _delegated_run_bundle() -> dict:
    token = _token()
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund", "send_email"],
        budget_usd=10.0,
        delegation=token,
    ) as r:
        with pytest.raises(AgentBrakeInterrupt):
            dispatch("send_email", {})
    return export_mod.build_export(r.flow_receipts(), signer=SIGNER)


def _passing(report: dict, name: str) -> bool:
    return next(c["ok"] for c in report["checks"] if c["name"] == name)


def test_export_deep_check_reverifies_embedded_tokens():
    bundle = json.loads(json.dumps(_delegated_run_bundle()))
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"], report["checks"]
    assert _passing(report, "delegation_tokens") is True


def test_export_deep_check_catches_tampered_embedded_token():
    bundle = _delegated_run_bundle()
    # Tamper the token INSIDE the receipt: flip the delegated scope. The
    # receipt row itself is re-signed nowhere, so first re-sign... an attacker
    # cannot: altering the embedded payload breaks the receipt signature, and
    # a receipt forged around a tampered token still fails the deep check.
    entry = bundle["entries"][0]
    att = json.loads(entry["attestation_json"])
    att["delegation"]["links"][0]["token_json"] = att["delegation"]["links"][0][
        "token_json"
    ].replace('"delegatee":"finance-agent"', '"delegatee":"evil-agent"')
    forged_json = attest.canonical_json(att, strict=True)
    entry["attestation_json"] = forged_json
    entry["signature"] = attest.sign_body(forged_json)  # attacker re-signs receipt
    entry["entry_hash"] = attest.entry_hash(forged_json, entry["signature"])
    # Rebuild a consistent bundle around the forged row (attacker has the
    # receipt key in this scenario — the WORST case for us).
    rows = [dict(e) for e in bundle["entries"]]
    fixed = []
    prev = "0" * 64
    for row in rows:
        att_row = json.loads(row["attestation_json"])
        att_row["prev_hash"] = prev
        row_json = attest.canonical_json(att_row, strict=True)
        sig = attest.sign_body(row_json)
        fixed.append(
            {
                "seq": att_row["seq"],
                "attestation_json": row_json,
                "signature": sig,
                "prev_hash": prev,
                "entry_hash": attest.entry_hash(row_json, sig),
            }
        )
        prev = fixed[-1]["entry_hash"]
    rebuilt = export_mod.build_export(
        [dict(f, attestation=json.loads(f["attestation_json"]), run_id=None) for f in fixed],
        signer=SIGNER,
    )
    report = export_mod.verify_export(rebuilt, pinned_public_keys=PUBLIC_KEYS)
    # Receipts verify (attacker held the receipt key) — but the embedded
    # delegation token was signed by the DELEGATOR, and that signature broke.
    assert _passing(report, "signatures_and_chain") is True
    assert _passing(report, "delegation_tokens") is False
    assert report["ok"] is False


# --- compliance report -------------------------------------------------------------

def test_report_classifies_and_renders_delegation():
    bundle = _delegated_run_bundle()
    verification = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    report = report_mod.build_report(bundle, verification)

    assert report["summary"]["autonomous_blocks"] == 1  # the delegation block
    assert len(report["delegation_blocks"]) == 1
    assert len(report["delegation_lifecycle"]) == 1  # the acceptance
    assert report["human_decisions"] == []  # nothing here is a human decision

    doc = report_mod.render_markdown(report)
    assert "Delegation activity" in doc
    assert "acting under a delegation from `support-agent`" in doc
    assert "outside its delegated scope" in doc
    assert "Delegated-privilege misuse" in doc