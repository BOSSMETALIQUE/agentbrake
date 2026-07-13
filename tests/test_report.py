"""Compliance report: structured data, rendering, and honest failure banners."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agentbrake import cli, receipts, report as report_mod, signing
from agentbrake import export as export_mod
from agentbrake.server import attest, store
from agentbrake.types import RunState, ToolCall

TEST_SIGNER = signing.Ed25519Signer.from_seed(b"\x06" * 32)
PUBLIC_KEYS = {TEST_SIGNER.key_id: TEST_SIGNER.public_key_hex()}


@pytest.fixture(autouse=True)
def _fixed_signer(monkeypatch: pytest.MonkeyPatch):
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


def _flow_bundle(n: int = 2) -> dict:
    ledger = receipts.InMemoryLedger()
    state = RunState()
    for _ in range(n):
        receipts.mint_flow_receipt(
            ledger, run_state=state, sink_call=ToolCall(name="send_email"), flow=_flow()
        )
    return export_mod.build_export(ledger.all(), signer=TEST_SIGNER)


def _human_bundle(tmp_path) -> dict:
    """A server-style chain with one kill and one approval."""
    db = tmp_path / "server.db"
    store.init_db(db)
    for i, decision in enumerate(["kill", "approve"]):
        attest.record_decision(
            {
                "id": f"int-{i}",
                "run_id": f"run-{i}",
                "reason": "ESCALATION" if decision == "kill" else "BUDGET",
                "context": {"tool": "delete_db" if decision == "kill" else "search"},
                "created_at": "2026-07-01T10:00:00+00:00",
                "decided_at": "2026-07-01T10:00:30+00:00",
            },
            decision,
            db_path=db,
        )
    return export_mod.build_export(store.get_attestation_chain(db_path=db), signer=TEST_SIGNER)


def _verified_report(bundle: dict, **kw) -> dict:
    verification = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    return report_mod.build_report(bundle, verification, **kw)


# --- structured data --------------------------------------------------------

def test_flow_blocks_are_counted_and_narrated():
    report = _verified_report(_flow_bundle(2))
    assert report["verification"]["ok"] is True
    assert report["summary"]["autonomous_blocks"] == 2
    assert report["summary"]["human_kills"] == 0
    assert report["events_in_period"] == 2
    event = report["flow_blocks"][0]
    assert event["tool"] == "send_email"
    assert event["evidence"]["seq"] == 1
    assert event["flow"]["tainted_by"][0]["source_tool"] == "read_webpage"


def test_human_decisions_are_split_by_outcome(tmp_path):
    report = _verified_report(_human_bundle(tmp_path))
    assert report["summary"]["human_kills"] == 1
    assert report["summary"]["human_approvals"] == 1
    assert report["summary"]["by_reason"] == {"escalation": 1, "budget": 1}
    assert report["summary"]["mean_decision_seconds"] == 30.0


def test_period_filter_excludes_events(tmp_path):
    bundle = _human_bundle(tmp_path)  # decided 2026-07-01
    report = _verified_report(
        bundle,
        period_start=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    assert report["events_in_period"] == 0
    # Verification still covers the whole chain.
    assert report["verification"]["entry_count"] == 2
    assert report["chain_length"] == 2


# --- rendering ----------------------------------------------------------------

def test_markdown_report_content(tmp_path):
    report = _verified_report(_human_bundle(tmp_path))
    doc = report_mod.render_markdown(report)
    assert "Evidence integrity: VERIFIED" in doc
    assert "Executive summary" in doc
    assert "Human decisions" in doc
    assert "**kill**" in doc and "**approve**" in doc
    assert "Tool outside the allow-list" in doc
    assert "receipt #1" in doc
    assert "Timestamps are self-reported" in doc


def test_markdown_flow_narrative():
    doc = report_mod.render_markdown(_verified_report(_flow_bundle(1)))
    assert "Attacks blocked automatically" in doc
    assert "read_webpage" in doc  # names the taint origin
    assert "blocked the call before it executed" in doc


def test_failed_verification_gets_a_warning_banner():
    bundle = _flow_bundle(2)
    bundle["entries"][0]["attestation_json"] = bundle["entries"][0][
        "attestation_json"
    ].replace('"decision":"block"', '"decision":"allow"')
    verification = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    doc = report_mod.render_markdown(report_mod.build_report(bundle, verification))
    assert "VERIFICATION FAILED" in doc
    assert "did NOT verify" in doc


def test_empty_period_renders_gracefully():
    doc = report_mod.render_markdown(
        _verified_report(
            _flow_bundle(1), period_start=datetime(2030, 1, 1, tzinfo=timezone.utc)
        )
    )
    assert "No enforcement events" in doc


# --- CLI ------------------------------------------------------------------------

def test_cli_report(tmp_path, capsys):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_flow_bundle(2)), encoding="utf-8")
    out_path = tmp_path / "report.md"

    code = cli.main(
        [
            "report", str(bundle_path),
            "-o", str(out_path),
            "--public-key", TEST_SIGNER.public_key_hex(),
        ]
    )
    assert code == 0
    assert "2 autonomous block(s)" in capsys.readouterr().out
    doc = out_path.read_text(encoding="utf-8")
    assert "Evidence integrity: VERIFIED" in doc


def test_cli_report_fails_loudly_on_bad_evidence(tmp_path, capsys):
    bundle = _flow_bundle(1)
    bundle["entries"][0]["signature"] = "00" * 64
    bundle_path = tmp_path / "bad.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    out_path = tmp_path / "report.md"

    code = cli.main(["report", str(bundle_path), "-o", str(out_path)])
    assert code == 1
    assert "VERIFICATION FAILED" in capsys.readouterr().out
    assert "did NOT verify" in out_path.read_text(encoding="utf-8")


def test_cli_report_period_filter(tmp_path, capsys):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_flow_bundle(1)), encoding="utf-8")
    out_path = tmp_path / "report.md"

    code = cli.main(
        [
            "report", str(bundle_path),
            "-o", str(out_path),
            "--from", "2030-01-01",
            "--public-key", TEST_SIGNER.public_key_hex(),
        ]
    )
    assert code == 0
    assert "0 event(s) in period" in capsys.readouterr().out