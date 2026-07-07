"""Signed, tamper-evident attestations for human approval/kill decisions.

A decision is no longer just a status flip — it produces a *receipt* that proves
what a human decided, on what information, at what time. Each attestation is:

* **Signed** — by default with Ed25519 (schema v2), so a third party holding
  only the *public* key can verify every record without being able to forge
  one. Legacy deployments pinned to ``AGENTBRAKE_SIGNING_KEY`` keep signing
  with HMAC-SHA256, which is integrity-only: whoever can verify can forge, so
  it proves nothing to an outside auditor (see :mod:`agentbrake.signing`).
* **Chained** to the previous attestation via ``prev_hash``, so the whole log is
  tamper-evident: you can't alter or delete one entry without breaking the link
  to the next.

This is the foundation for making agent actions *provable*, not just stoppable.

Layout of one attestation (the signed object, schema v2):

    {
      "version": "2",
      "alg": "ed25519",               # or "hmac-sha256" (legacy key)
      "key_id": "…",                  # identifies the signing key (rotation)
      "chain_id": "…",                # identifies THIS chain (anti-replay)
      "seq": 1,                       # monotonic, 1-based
      "interrupt_id": "...",
      "run_id": "...",
      "agent_id": null,               # if the context carried one
      "decision": "approve" | "kill",
      "reason": "loop" | "budget" | "escalation" | ...,
      "tool": "delete_database",
      "tool_args_digest": "sha256:...",   # digest of the tool call, not raw args
      "created_at": "...",            # when the interrupt fired
      "decided_at": "...",            # when the human decided
      "pending_seconds": 12.5,        # decided_at - created_at
      "info_digest": "sha256:...",    # digest of exactly what the UI showed
      "info_summary": { ... },        # small human-readable gist of that info
      "prev_hash": "<entry_hash of seq-1, or GENESIS>"
    }

v2 signatures cover ``DOMAIN_ATTESTATION_V2 + canonical_json`` so they can never
be replayed in another context. The stored row keeps the canonical JSON, its
``signature``, ``prev_hash`` and the ``entry_hash`` = sha256(canonical_json +
"." + signature) that the next entry points back to.

Honest limitations (also see docs): the hash chain detects alteration,
insertion, deletion and reordering *within* the records you are shown — it
cannot by itself detect that the tail was cut off or the whole log dropped.
That is what the signed chain head in :mod:`agentbrake.export` is for. And the
holder of the private key can always regenerate a whole plausible history;
anchoring exported heads with the auditor is what closes that window.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from agentbrake import signing
from . import store

ATTESTATION_VERSION = "2"
GENESIS_HASH = "0" * 64  # prev_hash of the very first attestation
SIGNING_KEY_ENV = "AGENTBRAKE_SIGNING_KEY"

# Serializes the read-tail -> build -> sign -> insert sequence so two concurrent
# decisions can't fork the chain or collide on a sequence number.
_CHAIN_LOCK = threading.Lock()


def _resolve_key() -> Tuple[bytes, bool]:
    """Return (key_bytes, from_env). Generates a strong key if unset.

    Legacy v1 HMAC key. Kept so old chains stay verifiable; new records are
    signed by SIGNER below (Ed25519 unless the deployment pins this env var).
    """
    configured = os.environ.get(SIGNING_KEY_ENV)
    if configured:
        return configured.encode("utf-8"), True
    return secrets.token_urlsafe(32).encode("utf-8"), False


SIGNING_KEY, SIGNING_KEY_FROM_ENV = _resolve_key()

# The active signer for NEW attestations (see signing.resolve_signer_from_env
# for the resolution order). Module global, looked up at call time so tests can
# pin a deterministic key.
SIGNER, SIGNER_SOURCE = signing.resolve_signer_from_env()


# ----- canonical encoding & primitives -----------------------------------

def canonical_json(obj: Any, *, strict: bool = False) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Stable across processes.

    ``strict=True`` (used for every signed body we build ourselves) rejects
    non-JSON types and NaN/Infinity instead of coercing them — coercion via
    ``str()`` is not stable across processes for unordered types like ``set``,
    and NaN produces JSON that other parsers refuse. The lenient default is
    kept for digests over *caller-supplied* data, where raising would turn a
    logging path into a crash; the digest then binds to the coerced form.
    """
    if strict:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _key_bytes(key: Optional[Any]) -> bytes:
    """Accept the module key (bytes), an explicit str, or bytes."""
    if key is None:
        return SIGNING_KEY  # module global, looked up at call time (test-friendly)
    if isinstance(key, str):
        return key.encode("utf-8")
    return key


def sign(attestation_json: str, key: Optional[Any] = None) -> str:
    """v1 primitive: HMAC-SHA256 of the bare canonical JSON, hex-encoded.

    Kept verbatim so v1 chains verify byte-for-byte. New records go through
    :func:`sign_body`, which uses the active SIGNER and domain separation.
    """
    return hmac.new(_key_bytes(key), attestation_json.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(attestation_json: str, signature: str, key: Optional[Any] = None) -> bool:
    """v1 primitive: True iff ``signature`` is a valid HMAC for the bare JSON."""
    expected = sign(attestation_json, key)
    return hmac.compare_digest(expected, signature)


def sign_body(attestation_json: str) -> str:
    """Sign a v2 attestation body with the active signer (domain-separated)."""
    return SIGNER.sign(signing.DOMAIN_ATTESTATION_V2 + attestation_json.encode("utf-8"))


def entry_hash(attestation_json: str, signature: str) -> str:
    """Chain hash for one entry; the next entry's ``prev_hash`` points here."""
    return _sha256_hex(attestation_json + "." + signature)


# ----- digests over the tool call and the displayed info -----------------

def tool_call_digest(context: Dict[str, Any]) -> str:
    """SHA-256 over the tool call in question (name + visible call history).

    We digest rather than store raw args: args may be large or sensitive, but a
    digest still binds the receipt to exactly which call was decided on. Note a
    digest is a *commitment* — it only proves something to an auditor if the
    raw context is retained somewhere and can be re-hashed against it.
    """
    tool_name = context.get("tool") or context.get("tool_name")
    run_state = context.get("run_state") or {}
    calls = run_state.get("calls") or [] if isinstance(run_state, dict) else []
    subject = {
        "tool": tool_name,
        "calls": [{"name": c.get("name"), "args": c.get("args", {})} for c in calls],
    }
    return "sha256:" + _sha256_hex(canonical_json(subject))


def info_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    """Small human-readable gist of what the validation UI displayed."""
    run_state = context.get("run_state") or {}
    calls = run_state.get("calls") or [] if isinstance(run_state, dict) else []
    return {
        "tool": context.get("tool") or context.get("tool_name"),
        "total_cost_usd": context.get("total_cost_usd", 0.0),
        "num_calls": len(calls),
    }


def info_digest(context: Dict[str, Any]) -> str:
    """SHA-256 over the full context shown to the approver (tamper-binds it)."""
    return "sha256:" + _sha256_hex(canonical_json(context))


def _pending_seconds(created_at: Optional[str], decided_at: Optional[str]) -> float:
    """decided_at - created_at in seconds (0.0 if either is unparseable)."""
    if not created_at or not decided_at:
        return 0.0
    try:
        delta = datetime.fromisoformat(decided_at) - datetime.fromisoformat(created_at)
    except ValueError:
        return 0.0
    return round(delta.total_seconds(), 3)


# ----- building & recording ----------------------------------------------

def build_attestation(
    *,
    seq: int,
    prev_hash: str,
    interrupt_record: Dict[str, Any],
    decision: str,
    chain_id: str,
) -> Dict[str, Any]:
    """Assemble the (unsigned) attestation object from a decided interrupt."""
    ctx = interrupt_record.get("context") or {}
    return {
        "version": ATTESTATION_VERSION,
        "alg": SIGNER.alg,
        "key_id": SIGNER.key_id,
        "chain_id": chain_id,
        "seq": seq,
        "interrupt_id": interrupt_record["id"],
        "run_id": interrupt_record.get("run_id") or ctx.get("run_id"),
        "agent_id": ctx.get("agent_id"),
        "decision": decision,
        "reason": (interrupt_record.get("reason") or "").lower(),
        "tool": ctx.get("tool") or ctx.get("tool_name"),
        "tool_args_digest": tool_call_digest(ctx),
        "created_at": interrupt_record.get("created_at"),
        "decided_at": interrupt_record.get("decided_at"),
        "pending_seconds": _pending_seconds(
            interrupt_record.get("created_at"), interrupt_record.get("decided_at")
        ),
        "info_digest": info_digest(ctx),
        "info_summary": info_summary(ctx),
        "prev_hash": prev_hash,
    }


def chain_id_from_tail(tail: Optional[Dict[str, Any]]) -> str:
    """Continue the tail's chain_id, or mint a fresh one at genesis.

    A v1 tail has no chain_id; the first v2 entry then introduces one, and
    every later entry must carry the same (verify_chain enforces this).
    """
    if tail:
        existing = (tail.get("attestation") or {}).get("chain_id")
        if existing:
            return existing
    return str(uuid4())


def record_decision(
    interrupt_record: Dict[str, Any],
    decision: str,
    db_path=None,
) -> Dict[str, Any]:
    """Build, sign, chain and persist the attestation for one decision.

    Returns the stored row (parsed). Serialized under a lock so the chain stays
    linear under concurrent decisions.
    """
    with _CHAIN_LOCK:
        tail = store.get_chain_tail(db_path=db_path)
        seq = (tail["seq"] + 1) if tail else 1
        prev_hash = tail["entry_hash"] if tail else GENESIS_HASH

        attestation = build_attestation(
            seq=seq,
            prev_hash=prev_hash,
            interrupt_record=interrupt_record,
            decision=decision,
            chain_id=chain_id_from_tail(tail),
        )
        attestation_json = canonical_json(attestation, strict=True)
        signature = sign_body(attestation_json)
        e_hash = entry_hash(attestation_json, signature)

        store.insert_attestation(
            seq=seq,
            interrupt_id=interrupt_record["id"],
            attestation_json=attestation_json,
            signature=signature,
            prev_hash=prev_hash,
            entry_hash=e_hash,
            db_path=db_path,
        )

    return {
        "seq": seq,
        "interrupt_id": interrupt_record["id"],
        "attestation": attestation,
        "attestation_json": attestation_json,
        "signature": signature,
        "prev_hash": prev_hash,
        "entry_hash": e_hash,
    }


# ----- verification --------------------------------------------------------

def verify_record_signature(
    attestation: Dict[str, Any],
    attestation_json: str,
    signature: str,
    *,
    public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
) -> Tuple[bool, Optional[str]]:
    """Verify one record's signature under whichever scheme it declares.

    * v1 (no ``alg`` field): HMAC over the bare JSON, under ``hmac_key`` or the
      module's legacy SIGNING_KEY. Integrity-only — the verifier holds the key.
    * v2 ed25519: verified under the public key matching the record's
      ``key_id``, taken from ``public_keys`` ({key_id: public_key_hex}) or from
      the module SIGNER if it is the same key. Third-party verifiable.
    * v2 hmac-sha256 (legacy env deployments): domain-separated HMAC.

    Returns ``(ok, error)`` — error explains a structural failure (unknown
    algorithm, no key available) as opposed to a plain signature mismatch.
    """
    alg = attestation.get("alg")
    if alg is None:
        return verify_signature(attestation_json, signature, key=hmac_key), None

    message = signing.DOMAIN_ATTESTATION_V2 + attestation_json.encode("utf-8")

    if alg == signing.ALG_ED25519:
        key_id = attestation.get("key_id")
        public_key = (public_keys or {}).get(key_id)
        if public_key is None and SIGNER.alg == signing.ALG_ED25519 and SIGNER.key_id == key_id:
            public_key = SIGNER.public_key_hex()
        if public_key is None:
            return False, f"no public key known for key_id={key_id}"
        return signing.verify_ed25519(public_key, message, signature), None

    if alg == signing.ALG_HMAC_SHA256:
        key = hmac_key if hmac_key is not None else _key_bytes(None)
        return signing.HmacSigner(key).verify(message, signature), None

    return False, f"unknown signature algorithm {alg!r}"


def verify_record(
    record: Dict[str, Any],
    *,
    public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
) -> bool:
    """Convenience: signature verdict for one stored row (parsed or raw)."""
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        attestation = json.loads(record["attestation_json"])
    ok, _ = verify_record_signature(
        attestation,
        record["attestation_json"],
        record["signature"],
        public_keys=public_keys,
        hmac_key=hmac_key,
    )
    return ok


def verify_chain(
    records: List[Dict[str, Any]],
    *,
    public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
) -> Tuple[bool, Optional[str]]:
    """Check a seq-ordered list of attestation rows for integrity.

    Detects: a bad/forged signature, an altered field (signature no longer
    matches), a broken link (prev_hash mismatch), a deleted entry (a gap in the
    consecutive sequence numbers), and a chain_id switch (records spliced in
    from another chain). Returns (ok, error_message).

    What this CANNOT detect on its own: a chain truncated at the tail, or a
    chain wiped entirely — a shorter (or empty) prefix is still a valid chain.
    Compare against a signed chain head (see agentbrake.export) to close that.
    """
    expected_prev = GENESIS_HASH
    expected_seq = 1
    expected_chain_id: Optional[str] = None
    for rec in records:
        seq = rec["seq"]
        att_json = rec["attestation_json"]
        signature = rec["signature"]

        if seq != expected_seq:
            return False, f"non-consecutive sequence at seq={seq} (expected {expected_seq}) — entry deleted?"

        try:
            attestation = json.loads(att_json)
        except json.JSONDecodeError:
            return False, f"unparseable attestation at seq={seq}"
        if attestation.get("seq") != seq:
            return False, f"seq mismatch at seq={seq}: signed body says {attestation.get('seq')}"

        ok, err = verify_record_signature(
            attestation, att_json, signature, public_keys=public_keys, hmac_key=hmac_key
        )
        if not ok:
            detail = f" ({err})" if err else ""
            return False, f"invalid signature at seq={seq} — entry altered or key unknown{detail}"

        chain_id = attestation.get("chain_id")
        if chain_id is not None:
            if expected_chain_id is None:
                expected_chain_id = chain_id
            elif chain_id != expected_chain_id:
                return False, f"chain_id switch at seq={seq} — entry from a different chain?"

        embedded_prev = attestation.get("prev_hash")
        if rec["prev_hash"] != embedded_prev:
            return False, f"stored prev_hash disagrees with signed body at seq={seq}"
        if embedded_prev != expected_prev:
            return False, f"broken chain link at seq={seq}"

        recomputed = entry_hash(att_json, signature)
        if recomputed != rec["entry_hash"]:
            return False, f"entry hash mismatch at seq={seq}"

        expected_prev = recomputed
        expected_seq += 1

    return True, None


def signing_banner() -> str:
    """Signing-key summary for the SERVER console only."""
    lines = ["-" * 66]
    if SIGNER.alg == signing.ALG_ED25519:
        lines.append(f"  Attestation signing: Ed25519 (key_id {SIGNER.key_id})")
        lines.append(f"  Public key (share with auditors): {SIGNER.public_key_hex()}")
        if SIGNER_SOURCE == "generated":
            lines.append("  Key was GENERATED for this process — persist it or receipts")
            lines.append("  minted now become unverifiable after restart:")
            lines.append(f"      {signing.SIGNING_SEED_ENV}={SIGNER.seed_hex()}")
        elif SIGNER_SOURCE == "key_file":
            lines.append(f"  Private key: from ${signing.SIGNING_KEY_FILE_ENV}")
        else:
            lines.append(f"  Private key: from ${signing.SIGNING_SEED_ENV}")
    else:
        lines.append("  Attestation signing: HMAC-SHA256 (legacy AGENTBRAKE_SIGNING_KEY)")
        lines.append("  WARNING: HMAC receipts are integrity-only — anyone who can")
        lines.append("  verify them can also forge them. For third-party verifiable")
        lines.append(f"  receipts, set {signing.SIGNING_SEED_ENV} or {signing.SIGNING_KEY_FILE_ENV}.")
    lines.append("  Decisions now produce signed receipts at /attestations.")
    lines.append("=" * 66)
    return "\n".join(lines)
