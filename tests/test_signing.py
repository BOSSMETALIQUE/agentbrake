"""Unit tests for the signing backends (Ed25519 + legacy HMAC)."""

from __future__ import annotations

import pytest

from agentbrake import signing


# --- Ed25519 ---------------------------------------------------------------

def test_ed25519_sign_verify_roundtrip():
    signer = signing.Ed25519Signer.generate()
    sig = signer.sign(b"message")
    assert signer.verify(b"message", sig) is True
    assert signer.verify(b"other", sig) is False


def test_ed25519_public_only_verification():
    """The core property: verification needs no private material."""
    signer = signing.Ed25519Signer.generate()
    sig = signer.sign(b"message")
    verifier = signing.Ed25519Verifier(signer.public_key_hex())
    assert verifier.verify(b"message", sig) is True
    assert verifier.verify(b"tampered", sig) is False
    assert verifier.key_id == signer.key_id


def test_ed25519_wrong_key_rejects():
    a, b = signing.Ed25519Signer.generate(), signing.Ed25519Signer.generate()
    sig = a.sign(b"message")
    assert signing.Ed25519Verifier(b.public_key_hex()).verify(b"message", sig) is False


def test_ed25519_seed_is_deterministic():
    seed = b"\x07" * 32
    a = signing.Ed25519Signer.from_seed(seed)
    b = signing.Ed25519Signer.from_seed_hex(seed.hex())
    assert a.public_key_hex() == b.public_key_hex()
    assert a.key_id == b.key_id
    assert a.seed_hex() == seed.hex()


def test_ed25519_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        signing.Ed25519Signer.from_seed(b"short")
    with pytest.raises(ValueError):
        signing.Ed25519Signer.from_seed_hex("not-hex")


def test_ed25519_pem_file_roundtrip(tmp_path):
    signer = signing.Ed25519Signer.generate()
    pem = tmp_path / "key.pem"
    pem.write_bytes(signer.private_pem())
    loaded = signing.Ed25519Signer.from_pem_file(str(pem))
    assert loaded.public_key_hex() == signer.public_key_hex()


def test_verify_tolerates_malformed_signature_and_key():
    signer = signing.Ed25519Signer.generate()
    verifier = signing.Ed25519Verifier(signer.public_key_hex())
    assert verifier.verify(b"m", "zz-not-hex") is False
    assert signing.verify_ed25519("deadbeef", b"m", signer.sign(b"m")) is False  # short key


# --- HMAC (legacy) -----------------------------------------------------------

def test_hmac_signer_roundtrip_and_key_id():
    signer = signing.HmacSigner(b"secret")
    sig = signer.sign(b"message")
    assert signer.verify(b"message", sig) is True
    assert signer.verify(b"other", sig) is False
    assert signer.public_key_hex() is None  # nothing safe to publish
    # key_id is stable and does not leak the key length/content trivially.
    assert signer.key_id == signing.HmacSigner(b"secret").key_id
    assert signer.key_id != signing.HmacSigner(b"other").key_id


# --- env resolution -----------------------------------------------------------

def test_resolver_prefers_key_file(tmp_path, monkeypatch):
    signer = signing.Ed25519Signer.generate()
    pem = tmp_path / "key.pem"
    pem.write_bytes(signer.private_pem())
    monkeypatch.setenv(signing.SIGNING_KEY_FILE_ENV, str(pem))
    monkeypatch.setenv(signing.SIGNING_SEED_ENV, ("00" * 32))
    resolved, source = signing.resolve_signer_from_env()
    assert source == "key_file"
    assert resolved.public_key_hex() == signer.public_key_hex()


def test_resolver_uses_seed_env(monkeypatch):
    monkeypatch.delenv(signing.SIGNING_KEY_FILE_ENV, raising=False)
    monkeypatch.setenv(signing.SIGNING_SEED_ENV, ("ab" * 32))
    resolved, source = signing.resolve_signer_from_env()
    assert source == "seed_env"
    assert resolved.alg == signing.ALG_ED25519


def test_resolver_falls_back_to_legacy_hmac(monkeypatch):
    monkeypatch.delenv(signing.SIGNING_KEY_FILE_ENV, raising=False)
    monkeypatch.delenv(signing.SIGNING_SEED_ENV, raising=False)
    monkeypatch.setenv("AGENTBRAKE_SIGNING_KEY", "legacy-secret")
    resolved, source = signing.resolve_signer_from_env()
    assert source == "legacy_hmac_env"
    assert resolved.alg == signing.ALG_HMAC_SHA256


def test_resolver_generates_when_unset(monkeypatch):
    for var in (signing.SIGNING_KEY_FILE_ENV, signing.SIGNING_SEED_ENV, "AGENTBRAKE_SIGNING_KEY"):
        monkeypatch.delenv(var, raising=False)
    resolved, source = signing.resolve_signer_from_env()
    assert source == "generated"
    assert resolved.alg == signing.ALG_ED25519
