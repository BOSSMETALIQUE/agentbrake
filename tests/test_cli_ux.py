"""CLI ergonomics: --version, and verify output that never overclaims."""

from __future__ import annotations

import json

import pytest

import agentbrake
from agentbrake import cli, receipts, signing
from agentbrake import export as export_mod
from agentbrake.server import attest
from agentbrake.types import RunState

TEST_SIGNER = signing.Ed25519Signer.from_seed(b"\x0c" * 32)


@pytest.fixture(autouse=True)
def _fixed_signer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(attest, "SIGNER", TEST_SIGNER)


def _mint_rows(n: int = 2) -> list:
    ledger = receipts.InMemoryLedger()
    state = RunState()
    for i in range(n):
        receipts.mint_detector_receipt(
            ledger, detector_kind="loop", run_id=state.run_id, tool=f"t{i}"
        )
    return ledger.all()


def _write_bundle(tmp_path, bundle: dict):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


# --- --version ---------------------------------------------------------------

def test_version_flag_prints_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"agentbrake {agentbrake.__version__}"


# --- verify never claims guarantees it did not establish ---------------------

def test_verify_pass_prints_guarantees(tmp_path, capsys):
    path = _write_bundle(tmp_path, export_mod.build_export(_mint_rows(), signer=TEST_SIGNER))
    assert cli.main(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert "What this verification PROVES" in out
    assert "What FAILED" not in out
    assert "Verdict: VERIFIED" in out


def test_verify_failure_hides_guarantees_and_lists_failures(tmp_path, capsys):
    bundle = export_mod.build_export(_mint_rows(), signer=TEST_SIGNER)
    bundle["entries"][1]["signature"] = "00" * 64
    path = _write_bundle(tmp_path, bundle)

    assert cli.main(["verify", str(path)]) == 1
    out = capsys.readouterr().out
    assert "PROVES" not in out
    assert "What FAILED" in out
    assert "x signatures_and_chain:" in out
    assert "NOTHING is proven" in out
    assert "Verdict: VERIFICATION FAILED" in out


def test_verify_unknown_key_failure_makes_no_claim(tmp_path, capsys, monkeypatch):
    # The field case: receipts signed by a key that no longer exists, exported
    # with an unsigned head. Must fail without asserting any guarantee.
    bundle = export_mod.build_export(_mint_rows(), signer=None)
    path = _write_bundle(tmp_path, bundle)
    # The verifier's process holds a different key, as on any other machine.
    monkeypatch.setattr(attest, "SIGNER", signing.Ed25519Signer.from_seed(b"\x0d" * 32))

    assert cli.main(["verify", str(path)]) == 1
    out = capsys.readouterr().out
    assert "PROVES" not in out
    assert "no public key known" in out
    assert "x head_signature:" in out


def _write_ledger(tmp_path, rows: list):
    path = tmp_path / "receipts.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return path


@pytest.mark.parametrize("n_rows", [1, 3])
def test_verify_on_raw_ledger_points_to_export(tmp_path, capsys, n_rows):
    # One row parses as a JSON object, several do not parse at all: both are
    # the same user mistake and get the same short answer.
    path = _write_ledger(tmp_path, _mint_rows(n_rows))

    assert cli.main(["verify", str(path)]) == 2
    captured = capsys.readouterr()
    assert "raw receipt ledger" in captured.err
    assert f"agentbrake export --receipts {path}" in captured.err
    assert "VERIFICATION FAILED" not in captured.out
    assert "entries:" not in captured.out


def test_verify_receipt_on_raw_ledger_points_to_prove(tmp_path, capsys):
    path = _write_ledger(tmp_path, _mint_rows(2))
    assert cli.main(["verify-receipt", str(path)]) == 2
    assert f"agentbrake prove --receipts {path}" in capsys.readouterr().err


def test_report_on_raw_ledger_points_to_export(tmp_path, capsys):
    path = _write_ledger(tmp_path, _mint_rows(2))
    assert cli.main(["report", str(path), "-o", str(tmp_path / "r.md")]) == 2
    assert "raw receipt ledger" in capsys.readouterr().err
    assert not (tmp_path / "r.md").exists()


def test_verify_on_unrelated_json_is_still_a_plain_failure(tmp_path, capsys):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    assert cli.main(["verify", str(path)]) == 1
    assert "raw receipt ledger" not in capsys.readouterr().err


def test_verify_receipt_failure_hides_guarantees(tmp_path, capsys):
    proof = export_mod.build_receipt_proof(_mint_rows(3), 2, signer=TEST_SIGNER)
    proof["entry"]["signature"] = "00" * 64
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof), encoding="utf-8")

    assert cli.main(["verify-receipt", str(path)]) == 1
    out = capsys.readouterr().out
    assert "PROVES" not in out
    assert "x entry_signature:" in out
