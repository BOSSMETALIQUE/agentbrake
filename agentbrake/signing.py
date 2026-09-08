"""Signing backends for attestations: Ed25519 (third-party verifiable) and HMAC.

Why two algorithms
------------------

HMAC-SHA256 (receipt schema v1) is *symmetric*: verifying a signature requires
the same key that creates one, so anyone who can verify can also forge. That is
fine for self-checks — detecting that someone edited the database under you —
but it is worthless as proof to a third party: handing an auditor the key hands
them a forgery kit, and withholding it leaves them nothing to check.

Ed25519 (receipt schema v2, the default) is *asymmetric*: the private key signs,
the public key verifies. An auditor holding only the public key can confirm
every receipt is authentic and unmodified, and could not have produced a single
one of them. This is the property that makes a receipt showable.

Key identity
------------

Every signer exposes a short ``key_id`` (hex) derived from its key material.
The id is embedded in each signed receipt so a verifier knows which key to
check against and so keys can be rotated without orphaning old receipts. The
``key_id`` is an *identifier*, not a security boundary — the signature itself
carries the security.

Domain separation
-----------------

v2 signatures are computed over ``DOMAIN + message``, where DOMAIN names the
exact context (attestation body vs. chain-head statement). A signature minted
for one context can therefore never be replayed as a signature for another,
even under the same key.

Honest limitations
------------------

* Whoever holds the *private* key can still rewrite history and re-sign it.
  Signatures prove authorship under a key, not that the log was never
  regenerated. Anchoring the chain head externally (export it, hand it to the
  auditor, pin it) is what bounds that window.
* In local mode the private key lives in the same process as the guarded
  agent. A fully compromised agent process can read the key and forge
  receipts. For adversarial-grade proof, sign on a separate trusted host
  (remote mode) or ship receipts off-box immediately.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALG_ED25519 = "ed25519"
ALG_HMAC_SHA256 = "hmac-sha256"

# Domain-separation prefixes: a signature is bound to exactly one context.
DOMAIN_ATTESTATION_V2 = b"agentbrake.attestation.v2\n"
DOMAIN_CHAIN_HEAD_V1 = b"agentbrake.chain-head.v1\n"
DOMAIN_DELEGATION_V1 = b"agentbrake.delegation.v1\n"

# Environment configuration, resolved by callers (see attest._resolve_signer):
#   AGENTBRAKE_SIGNING_KEY_FILE — path to an Ed25519 private key in PEM form.
#   AGENTBRAKE_SIGNING_SEED     — 64 hex chars: the raw 32-byte Ed25519 seed.
#   AGENTBRAKE_SIGNING_KEY      — legacy HMAC secret (v1-compatible deployments).
SIGNING_KEY_FILE_ENV = "AGENTBRAKE_SIGNING_KEY_FILE"
SIGNING_SEED_ENV = "AGENTBRAKE_SIGNING_SEED"

_KEY_ID_HEX_CHARS = 16


def _key_id_from(material: bytes, *, domain: bytes) -> str:
    """Short hex identifier for key material, domain-separated per algorithm."""
    return hashlib.sha256(domain + material).hexdigest()[:_KEY_ID_HEX_CHARS]


def key_id_for_public_key(public_key_bytes: bytes) -> str:
    """The key_id embedded in receipts signed by the matching private key."""
    return _key_id_from(public_key_bytes, domain=b"agentbrake.key-id.ed25519\n")


@runtime_checkable
class Signer(Protocol):
    """Anything that can sign attestation bytes and identify its key."""

    alg: str

    @property
    def key_id(self) -> str: ...
    def sign(self, message: bytes) -> str: ...
    def verify(self, message: bytes, signature_hex: str) -> bool: ...
    def public_key_hex(self) -> Optional[str]: ...


class Ed25519Signer:
    """Signs with an Ed25519 private key; verifiable with only the public key."""

    alg = ALG_ED25519

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ----- constructors ----------------------------------------------------

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519Signer":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Ed25519Signer":
        try:
            seed = bytes.fromhex(seed_hex.strip())
        except ValueError as e:
            raise ValueError(f"{SIGNING_SEED_ENV} must be 64 hex characters") from e
        return cls.from_seed(seed)

    @classmethod
    def from_pem_file(cls, path: str) -> "Ed25519Signer":
        data = Path(path).expanduser().read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} does not contain an Ed25519 private key")
        return cls(key)

    # ----- key material ----------------------------------------------------

    @property
    def key_id(self) -> str:
        return key_id_for_public_key(self._public_bytes)

    def public_key_hex(self) -> str:
        """32-byte raw public key, hex — embed this in exports."""
        return self._public_bytes.hex()

    def seed_hex(self) -> str:
        """The raw 32-byte seed, hex — persist via AGENTBRAKE_SIGNING_SEED.

        Sensitive: whoever has the seed has the private key. Only surface this
        on the server's own console (see attest.signing_banner), never in any
        agent-reachable output.
        """
        raw = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw.hex()

    def private_pem(self) -> bytes:
        """PKCS8 PEM of the private key, for `agentbrake keygen` output."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # ----- sign / verify ---------------------------------------------------

    def sign(self, message: bytes) -> str:
        return self._private_key.sign(message).hex()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        return verify_ed25519(self._public_bytes.hex(), message, signature_hex)


class Ed25519Verifier:
    """Public-key-only verification — what a third party runs.

    Holds no private material: it can confirm signatures but cannot produce
    them. Built from the 32-byte raw public key in hex, as found in an export
    bundle's ``signing.public_key`` field.
    """

    alg = ALG_ED25519

    def __init__(self, public_key_hex: str):
        self._public_bytes = bytes.fromhex(public_key_hex)
        if len(self._public_bytes) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes (64 hex chars)")
        self._public_key = Ed25519PublicKey.from_public_bytes(self._public_bytes)

    @property
    def key_id(self) -> str:
        return key_id_for_public_key(self._public_bytes)

    def public_key_hex(self) -> str:
        return self._public_bytes.hex()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


def verify_ed25519(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """One-shot Ed25519 verification from hex-encoded key and signature."""
    try:
        return Ed25519Verifier(public_key_hex).verify(message, signature_hex)
    except ValueError:
        return False


class HmacSigner:
    """Legacy symmetric signer. Integrity self-checks only — NOT third-party proof.

    Kept so deployments pinned to AGENTBRAKE_SIGNING_KEY keep working. Any
    verifier of these receipts necessarily holds the forging key, so tools that
    consume them must label the result "integrity-checked under a shared key",
    never "independently verified".
    """

    alg = ALG_HMAC_SHA256

    def __init__(self, key: bytes):
        self._key = key

    @property
    def key_id(self) -> str:
        # Domain-separated digest of the secret: identifies the key without
        # doubling as a MAC oracle. Preimage resistance keeps the key private.
        return _key_id_from(self._key, domain=b"agentbrake.key-id.hmac\n")

    def public_key_hex(self) -> None:
        return None  # symmetric: there is nothing safe to publish

    def sign(self, message: bytes) -> str:
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        return hmac.compare_digest(self.sign(message), signature_hex)


def resolve_signer_from_env() -> "tuple[Signer, str]":
    """Build the process signer from the environment.

    Resolution order (first match wins) — returns ``(signer, source)`` where
    ``source`` names what was used, for the server banner:

    1. ``AGENTBRAKE_SIGNING_KEY_FILE`` — Ed25519 private key, PEM.
    2. ``AGENTBRAKE_SIGNING_SEED``     — Ed25519 raw seed, 64 hex chars.
    3. ``AGENTBRAKE_SIGNING_KEY``      — legacy HMAC secret (v1-era deployments).
    4. Nothing set — a fresh Ed25519 key is generated. Receipts minted under it
       stay verifiable only if the seed (printed on the server console) is
       persisted before the process exits.
    """
    key_file = os.environ.get(SIGNING_KEY_FILE_ENV)
    if key_file:
        return Ed25519Signer.from_pem_file(key_file), "key_file"
    seed = os.environ.get(SIGNING_SEED_ENV)
    if seed:
        return Ed25519Signer.from_seed_hex(seed), "seed_env"
    legacy = os.environ.get("AGENTBRAKE_SIGNING_KEY")
    if legacy:
        return HmacSigner(legacy.encode("utf-8")), "legacy_hmac_env"
    return Ed25519Signer.generate(), "generated"
