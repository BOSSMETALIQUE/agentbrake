"""Export bundles + standalone verification: the third-party trust path.

Every test here plays the role of an auditor: given only a bundle (and at most
a public key obtained out-of-band), can tampering, truncation, reordering, and
key substitution be detected — without ever contacting a server or holding a
private key?
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentbrake import cli, receipts, signing
from agentbrake import export as export_mod
from agentbrake.server import attest
from agentbrake.types import RunState, ToolCall

TEST_SIGNER = signing.Ed25519Signer.from_seed(b"\x04" * 32)
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


def _mint_chain(n: int = 3) -> list:
    ledger = receipts.InMemoryLedger()
    state = RunState()
    for i in range(n):
        receipts.mint_flow_receipt(
            ledger, run_state=state, sink_call=ToolCall(name=f"sink_{i}"), flow=_flow()
        )
    return ledger.all()


def _passing(report: dict, name: str) -> bool:
    return next(c["ok"] for c in report["checks"] if c["name"] == name)


# --- happy path --------------------------------------------------------------

def test_export_verifies_offline_with_public_key_only():
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    # Round-trip through JSON: the auditor sees a file, not Python objects.
    bundle = json.loads(json.dumps(bundle))
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"], report["checks"]
    assert report["third_party_verifiable"] is True
    assert report["entry_count"] == 3


def test_export_embeds_key_and_signed_head():
    bundle = export_mod.build_export(_mint_chain(2), signer=TEST_SIGNER)
    assert bundle["public_keys"] == PUBLIC_KEYS
    assert bundle["head"]["signature"] is not None
    assert bundle["head"]["statement"]["length"] == 2
    assert bundle["head"]["statement"]["head_hash"] == bundle["entries"][-1]["entry_hash"]
    # Entries carry only signed material — no parsed duplicate to mis-trust.
    assert set(bundle["entries"][0].keys()) == set(export_mod._ENTRY_FIELDS)


def test_empty_chain_exports_and_verifies():
    bundle = export_mod.build_export([], signer=TEST_SIGNER)
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"], report["checks"]
    assert report["third_party_verifiable"] is False  # nothing was attested


# --- tampering scenarios -------------------------------------------------------

def test_altered_entry_fails():
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    bundle["entries"][1]["attestation_json"] = bundle["entries"][1][
        "attestation_json"
    ].replace('"decision":"block"', '"decision":"allow"')
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "signatures_and_chain") is False


def test_deleted_middle_entry_fails():
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    del bundle["entries"][1]
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "signatures_and_chain") is False


def test_reordered_entries_fail():
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    bundle["entries"][0], bundle["entries"][1] = bundle["entries"][1], bundle["entries"][0]
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False


def test_truncated_tail_fails_against_signed_head():
    """The attack verify_chain alone cannot see: drop the last receipts."""
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    bundle["entries"] = bundle["entries"][:2]  # a valid chain — but shorter
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "signatures_and_chain") is True  # prefix IS valid
    assert _passing(report, "head_matches_entries") is False  # the head isn't


def test_truncation_with_rebuilt_head_fails_signature():
    """An attacker who truncates and rewrites the head cannot sign it."""
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    bundle["entries"] = bundle["entries"][:2]
    statement = dict(bundle["head"]["statement"])
    statement["length"] = 2
    statement["head_hash"] = bundle["entries"][-1]["entry_hash"]
    bundle["head"]["statement"] = statement  # forged commitment, stale signature
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "head_matches_entries") is True
    assert _passing(report, "head_signature") is False


def test_key_substitution_defeated_by_pinning():
    """An attacker re-mints the whole chain under their own key and embeds
    their own public key. An unpinned verifier accepts internal consistency;
    a verifier who pinned the real key rejects it. This asymmetry is exactly
    why the CLI tells unpinned users to compare the key_id out-of-band."""
    attacker = signing.Ed25519Signer.from_seed(b"\x05" * 32)
    ledger = receipts.InMemoryLedger()
    state = RunState()
    import unittest.mock

    with unittest.mock.patch.object(attest, "SIGNER", attacker):
        receipts.mint_flow_receipt(
            ledger, run_state=state, sink_call=ToolCall(name="sink"), flow=_flow()
        )
        forged = export_mod.build_export(ledger.all(), signer=attacker)

    # Internally consistent — the forger did sign their own fabrication...
    unpinned = export_mod.verify_export(forged)
    assert unpinned["ok"] is True
    # ...but it cannot impersonate the real key once the verifier pins it.
    pinned = export_mod.verify_export(forged, pinned_public_keys=PUBLIC_KEYS)
    assert pinned["ok"] is False


def test_unsigned_head_is_flagged():
    bundle = export_mod.build_export(
        _mint_chain(1), signer=None, extra_public_keys=PUBLIC_KEYS
    )
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "signatures_and_chain") is True
    assert _passing(report, "head_signature") is False
    assert report["third_party_verifiable"] is False


# --- rollback detection across exports (--expect-head) -------------------------

def test_expected_head_prefix_grows_ok():
    rows = _mint_chain(3)
    pinned_head = (2, rows[1]["entry_hash"])  # head the auditor saw last time
    bundle = export_mod.build_export(rows, signer=TEST_SIGNER)
    report = export_mod.verify_export(
        bundle, pinned_public_keys=PUBLIC_KEYS, expected_head=pinned_head
    )
    assert report["ok"], report["checks"]


def test_expected_head_detects_rollback():
    rows = _mint_chain(3)
    pinned_head = (3, rows[2]["entry_hash"])
    shorter = export_mod.build_export(rows[:2], signer=TEST_SIGNER)
    report = export_mod.verify_export(
        shorter, pinned_public_keys=PUBLIC_KEYS, expected_head=pinned_head
    )
    assert report["ok"] is False
    assert _passing(report, "expected_head") is False


def test_expected_head_detects_rewritten_history():
    rows = _mint_chain(3)
    bundle = export_mod.build_export(rows, signer=TEST_SIGNER)
    report = export_mod.verify_export(
        bundle,
        pinned_public_keys=PUBLIC_KEYS,
        expected_head=(3, "f" * 64),  # same length, different content
    )
    assert report["ok"] is False


# --- Merkle root in the signed head ---------------------------------------------

def test_head_carries_merkle_root():
    from agentbrake import merkle

    rows = _mint_chain(5)
    bundle = export_mod.build_export(rows, signer=TEST_SIGNER)
    statement = bundle["head"]["statement"]
    assert statement["tree_size"] == 5
    assert statement["tree_root"] == merkle.root_for_entries(bundle["entries"])


def test_swapped_root_fails_merkle_check():
    bundle = export_mod.build_export(_mint_chain(3), signer=TEST_SIGNER)
    bundle["head"]["statement"]["tree_root"] = "ab" * 32
    report = export_mod.verify_export(bundle, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False
    assert _passing(report, "merkle_root") is False
    assert _passing(report, "head_signature") is False  # statement was altered


# --- consistency between two exports ----------------------------------------------

def test_consistency_accepts_growing_chain():
    rows = _mint_chain(5)
    old = export_mod.build_export(rows[:3], signer=TEST_SIGNER)
    new = export_mod.build_export(rows, signer=TEST_SIGNER)
    report = export_mod.verify_export(
        new, pinned_public_keys=PUBLIC_KEYS, consistent_with=old
    )
    assert report["ok"], report["checks"]
    assert _passing(report, "consistency") is True


def test_consistency_detects_rewritten_prefix():
    rows = _mint_chain(3)
    old = export_mod.build_export(rows, signer=TEST_SIGNER)
    # A "new" chain that is NOT an extension of the old one.
    other_rows = _mint_chain(4)
    new = export_mod.build_export(other_rows, signer=TEST_SIGNER)
    report = export_mod.verify_export(
        new, pinned_public_keys=PUBLIC_KEYS, consistent_with=old
    )
    assert report["ok"] is False
    assert _passing(report, "consistency") is False


def test_consistency_detects_shrunken_chain():
    rows = _mint_chain(4)
    old = export_mod.build_export(rows, signer=TEST_SIGNER)
    new = export_mod.build_export(rows[:2], signer=TEST_SIGNER)
    report = export_mod.verify_export(
        new, pinned_public_keys=PUBLIC_KEYS, consistent_with=old
    )
    assert report["ok"] is False


def test_consistency_requires_signed_old_head():
    rows = _mint_chain(3)
    old = export_mod.build_export(rows[:2], signer=None, extra_public_keys=PUBLIC_KEYS)
    new = export_mod.build_export(rows, signer=TEST_SIGNER)
    report = export_mod.verify_export(
        new, pinned_public_keys=PUBLIC_KEYS, consistent_with=old
    )
    assert _passing(report, "old_head_signature") is False


# --- single-receipt proofs (selective disclosure) ----------------------------------

def test_receipt_proof_verifies_without_the_log():
    rows = _mint_chain(5)
    proof = export_mod.build_receipt_proof(rows, 3, signer=TEST_SIGNER)
    proof = json.loads(json.dumps(proof))  # what the recipient actually holds
    assert "entries" not in proof  # the rest of the log is NOT disclosed
    report = export_mod.verify_receipt_proof(proof, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"], report["checks"]
    assert report["third_party_verifiable"] is True


def test_receipt_proof_position_is_bound():
    """Moving the proof to another index must fail — position is proven."""
    rows = _mint_chain(5)
    proof = export_mod.build_receipt_proof(rows, 3, signer=TEST_SIGNER)
    proof["leaf_index"] = 3  # claim seq-3 receipt sits at position 3 (it's at 2)
    report = export_mod.verify_receipt_proof(proof, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False


def test_receipt_proof_tampered_entry_fails():
    rows = _mint_chain(5)
    proof = export_mod.build_receipt_proof(rows, 2, signer=TEST_SIGNER)
    proof["entry"]["attestation_json"] = proof["entry"]["attestation_json"].replace(
        '"decision":"block"', '"decision":"allow"'
    )
    report = export_mod.verify_receipt_proof(proof, pinned_public_keys=PUBLIC_KEYS)
    assert report["ok"] is False


def test_receipt_proof_from_foreign_log_fails():
    """A receipt + proof from one log cannot ride another log's signed head."""
    rows_a, rows_b = _mint_chain(4), _mint_chain(4)
    proof_a = export_mod.build_receipt_proof(rows_a, 2, signer=TEST_SIGNER)
    proof_b = export_mod.build_receipt_proof(rows_b, 2, signer=TEST_SIGNER)
    frankenstein = dict(proof_a, head=proof_b["head"])
    report = export_mod.verify_receipt_proof(
        frankenstein, pinned_public_keys=PUBLIC_KEYS
    )
    assert report["ok"] is False


def test_receipt_proof_bad_seq_raises():
    rows = _mint_chain(2)
    with pytest.raises(ValueError):
        export_mod.build_receipt_proof(rows, 9, signer=TEST_SIGNER)


# --- CLI end-to-end -------------------------------------------------------------

def _write_jsonl(rows: list, path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def test_cli_export_and_verify_roundtrip(tmp_path, monkeypatch, capsys):
    jsonl = tmp_path / "receipts.jsonl"
    _write_jsonl(_mint_chain(3), jsonl)
    bundle_path = tmp_path / "bundle.json"

    monkeypatch.setenv(signing.SIGNING_SEED_ENV, (b"\x04" * 32).hex())
    monkeypatch.delenv(signing.SIGNING_KEY_FILE_ENV, raising=False)
    assert cli.main(["export", "--receipts", str(jsonl), "-o", str(bundle_path)]) == 0

    # Unpinned verify: passes, but warns to compare the key out-of-band.
    assert cli.main(["verify", str(bundle_path)]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "out-of-band" in out

    # Pinned verify: the auditor supplies the trusted public key explicitly.
    code = cli.main(
        ["verify", str(bundle_path), "--public-key", TEST_SIGNER.public_key_hex()]
    )
    assert code == 0
    assert "PINNED" in capsys.readouterr().out


def test_cli_verify_fails_on_tampered_bundle(tmp_path, capsys):
    bundle = export_mod.build_export(_mint_chain(2), signer=TEST_SIGNER)
    bundle["entries"][0]["attestation_json"] = bundle["entries"][0][
        "attestation_json"
    ].replace('"decision":"block"', '"decision":"allow"')
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")

    assert cli.main(["verify", str(path)]) == 1
    assert "VERIFICATION FAILED" in capsys.readouterr().out


def test_cli_verify_json_report(tmp_path, capsys):
    bundle = export_mod.build_export(_mint_chain(1), signer=TEST_SIGNER)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")

    assert cli.main(["verify", str(path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["third_party_verifiable"] is True


def test_cli_verify_expect_head_detects_rollback(tmp_path, capsys):
    rows = _mint_chain(3)
    full_head = rows[2]["entry_hash"]
    shorter = export_mod.build_export(rows[:2], signer=TEST_SIGNER)
    path = tmp_path / "short.json"
    path.write_text(json.dumps(shorter), encoding="utf-8")

    code = cli.main(["verify", str(path), "--expect-head", f"3:{full_head}"])
    assert code == 1
    assert "truncated or rolled back" in capsys.readouterr().out


def test_cli_verify_consistent_with(tmp_path, capsys):
    rows = _mint_chain(4)
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    old_path.write_text(
        json.dumps(export_mod.build_export(rows[:2], signer=TEST_SIGNER)), encoding="utf-8"
    )
    new_path.write_text(
        json.dumps(export_mod.build_export(rows, signer=TEST_SIGNER)), encoding="utf-8"
    )
    code = cli.main(
        [
            "verify", str(new_path),
            "--public-key", TEST_SIGNER.public_key_hex(),
            "--consistent-with", str(old_path),
        ]
    )
    assert code == 0
    assert "exact prefix" in capsys.readouterr().out


def test_cli_prove_and_verify_receipt(tmp_path, monkeypatch, capsys):
    jsonl = tmp_path / "receipts.jsonl"
    _write_jsonl(_mint_chain(5), jsonl)
    proof_path = tmp_path / "proof.json"

    monkeypatch.setenv(signing.SIGNING_SEED_ENV, (b"\x04" * 32).hex())
    monkeypatch.delenv(signing.SIGNING_KEY_FILE_ENV, raising=False)
    assert cli.main(
        ["prove", "--receipts", str(jsonl), "--seq", "3", "-o", str(proof_path)]
    ) == 0

    code = cli.main(
        ["verify-receipt", str(proof_path), "--public-key", TEST_SIGNER.public_key_hex()]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "Merkle inclusion" in out

    # Tamper the disclosed receipt: verification must fail.
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["entry"]["signature"] = "00" * 64
    proof_path.write_text(json.dumps(proof), encoding="utf-8")
    assert cli.main(["verify-receipt", str(proof_path)]) == 1


def test_cli_prove_rejects_unknown_seq(tmp_path, monkeypatch):
    jsonl = tmp_path / "receipts.jsonl"
    _write_jsonl(_mint_chain(2), jsonl)
    monkeypatch.setenv(signing.SIGNING_SEED_ENV, (b"\x04" * 32).hex())
    assert cli.main(["prove", "--receipts", str(jsonl), "--seq", "7"]) == 2


def test_cli_keygen(tmp_path, capsys):
    pem = tmp_path / "key.pem"
    assert cli.main(["keygen", "-o", str(pem)]) == 0
    out = capsys.readouterr().out
    assert "public key:" in out
    loaded = signing.Ed25519Signer.from_pem_file(str(pem))
    assert loaded.public_key_hex() in out
    # Refuses to clobber an existing key.
    assert cli.main(["keygen", "-o", str(pem)]) == 2


# --- run integration -------------------------------------------------------------

def test_run_export_receipts(tmp_path):
    import agentbrake
    from agentbrake import AgentBrakeInterrupt, block_exfiltration

    agentbrake._default_run = None

    @agentbrake.guard()
    def dispatch(name: str, args: dict) -> str:
        return "ok"

    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ) as r:
        dispatch("read_webpage", {"url": "http://evil"})
        with pytest.raises(AgentBrakeInterrupt):
            dispatch("send_email", {"to": "attacker@evil.com"})

    out = tmp_path / "bundle.json"
    bundle = r.export_receipts(str(out))
    assert out.exists()
    report = export_mod.verify_export(
        json.loads(out.read_text(encoding="utf-8")),
        pinned_public_keys=PUBLIC_KEYS,
    )
    assert report["ok"], report["checks"]
    assert bundle["entries"][0]["seq"] == 1
    agentbrake._default_run = None
