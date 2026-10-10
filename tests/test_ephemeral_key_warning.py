"""Durable receipts under an ephemeral key are flagged, never silently written."""

from __future__ import annotations

import json
import warnings

import pytest

import agentbrake
from agentbrake import cli, receipts, signing
from agentbrake import export as export_mod
from agentbrake.server import attest
from agentbrake.signing import EphemeralSigningKeyWarning

# Factory keys from fixed seeds: test material only.
GENERATED = signing.Ed25519Signer.from_seed(b"\x10" * 32)
CONFIGURED = signing.Ed25519Signer.from_seed(b"\x11" * 32)


@pytest.fixture(autouse=True)
def _isolate():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@pytest.fixture()
def ephemeral(monkeypatch: pytest.MonkeyPatch):
    """Simulate a process that started with no signing key configured."""
    monkeypatch.setattr(attest, "SIGNER", GENERATED)
    monkeypatch.setattr(attest, "_RESOLVED_SIGNER", GENERATED)
    monkeypatch.setattr(attest, "SIGNER_SOURCE", "generated")


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return "ok"


def test_receipts_path_with_ephemeral_key_warns(ephemeral, tmp_path):
    path = tmp_path / "receipts.jsonl"
    with pytest.warns(EphemeralSigningKeyWarning) as record:
        agentbrake.run(allowed_tools=["t"], receipts_path=str(path))
    message = str(record[0].message)
    assert str(path) in message
    assert GENERATED.key_id in message
    assert "agentbrake keygen" in message
    assert signing.SIGNING_KEY_FILE_ENV in message


def test_init_with_receipts_path_warns_too(ephemeral, tmp_path):
    with pytest.warns(EphemeralSigningKeyWarning):
        agentbrake.init(allowed_tools=["t"], receipts_path=str(tmp_path / "r.jsonl"))


def test_in_memory_receipts_do_not_warn(ephemeral):
    # Nothing outlives the process, and in-process verification still works.
    with warnings.catch_warnings():
        warnings.simplefilter("error", EphemeralSigningKeyWarning)
        with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
            with pytest.raises(agentbrake.AgentBrakeInterrupt):
                dispatch("nope", {})
    assert r.verify_receipts() == (True, None)


@pytest.mark.parametrize("source", ["key_file", "seed_env", "legacy_hmac_env"])
def test_configured_key_does_not_warn(monkeypatch, tmp_path, source):
    monkeypatch.setattr(attest, "SIGNER", CONFIGURED)
    monkeypatch.setattr(attest, "_RESOLVED_SIGNER", CONFIGURED)
    monkeypatch.setattr(attest, "SIGNER_SOURCE", source)
    with warnings.catch_warnings():
        warnings.simplefilter("error", EphemeralSigningKeyWarning)
        agentbrake.run(allowed_tools=["t"], receipts_path=str(tmp_path / "r.jsonl"))


def test_signer_installed_after_import_does_not_warn(monkeypatch, tmp_path):
    # An embedding app (or a test) that installs its own key is not ephemeral,
    # even though the env resolution at import time generated one.
    monkeypatch.setattr(attest, "_RESOLVED_SIGNER", GENERATED)
    monkeypatch.setattr(attest, "SIGNER_SOURCE", "generated")
    monkeypatch.setattr(attest, "SIGNER", CONFIGURED)
    assert attest.signer_is_ephemeral() is False
    with warnings.catch_warnings():
        warnings.simplefilter("error", EphemeralSigningKeyWarning)
        agentbrake.run(allowed_tools=["t"], receipts_path=str(tmp_path / "r.jsonl"))


def test_warning_changes_nothing_in_the_receipts(ephemeral, tmp_path):
    path = tmp_path / "receipts.jsonl"
    with pytest.warns(EphemeralSigningKeyWarning):
        with agentbrake.run(allowed_tools=["t"], budget_usd=1.0, receipts_path=str(path)):
            with pytest.raises(agentbrake.AgentBrakeInterrupt):
                dispatch("nope", {})
    rows = export_mod.rows_from_jsonl(str(path))
    assert len(rows) == 1
    assert set(rows[0]) == {
        "seq", "run_id", "attestation", "attestation_json", "signature", "prev_hash", "entry_hash"
    }
    # Same verifier as before: valid under the key that signed them...
    assert receipts.verify_chain(
        rows, public_keys={GENERATED.key_id: GENERATED.public_key_hex()}
    ) == (True, None)


def test_verify_explains_the_unknown_key(ephemeral, tmp_path, monkeypatch, capsys):
    path = tmp_path / "receipts.jsonl"
    with pytest.warns(EphemeralSigningKeyWarning):
        with agentbrake.run(allowed_tools=["t"], budget_usd=1.0, receipts_path=str(path)):
            with pytest.raises(agentbrake.AgentBrakeInterrupt):
                dispatch("nope", {})

    # Later, in another process: the ephemeral key is gone.
    monkeypatch.setattr(attest, "SIGNER", signing.Ed25519Signer.from_seed(b"\x12" * 32))
    bundle_path = tmp_path / "bundle.json"
    bundle = export_mod.build_export(export_mod.rows_from_jsonl(str(path)), signer=None)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    assert cli.main(["verify", str(bundle_path)]) == 1
    out = capsys.readouterr().out
    assert "no public key known" in out
    assert "ephemeral key" in out
    assert "PROVES" not in out
