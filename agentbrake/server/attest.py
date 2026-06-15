"""Signed, tamper-evident attestations for human approval/kill decisions.

A decision is no longer just a status flip — it produces a *receipt* that proves
what a human decided, on what information, at what time. Each attestation is:

* **Signed** with HMAC-SHA256 under a server-side key, so a single record can't
  be altered without detection (you'd need the key to forge the signature).
* **Chained** to the previous attestation via ``prev_hash``, so the whole log is
  tamper-evident: you can't alter or delete one entry without breaking the link
  to the next.

This is the foundation for making agent actions *provable*, not just stoppable.

Layout of one attestation (the signed object):

    {
      "version": "1",
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

The stored row keeps the canonical JSON, its ``signature``, ``prev_hash`` and the
``entry_hash`` = sha256(canonical_json + "." + signature) that the next entry
points back to.
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

from . import store

ATTESTATION_VERSION = "1"
GENESIS_HASH = "0" * 64  # prev_hash of the very first attestation
SIGNING_KEY_ENV = "AGENTBRAKE_SIGNING_KEY"

# Serializes the read-tail -> build -> sign -> insert sequence so two concurrent
# decisions can't fork the chain or collide on a sequence number.
_CHAIN_LOCK = threading.Lock()


def _resolve_key() -> Tuple[bytes, bool]:
    """Return (key_bytes, from_env). Generates a strong key if unset."""
    configured = os.environ.get(SIGNING_KEY_ENV)
    if configured:
        return configured.encode("utf-8"), True
    return secrets.token_urlsafe(32).encode("utf-8"), False


SIGNING_KEY, SIGNING_KEY_FROM_ENV = _resolve_key()


# ----- canonical encoding & primitives -----------------------------------

def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Stable across processes."""
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
    """HMAC-SHA256 of the canonical attestation JSON, hex-encoded."""
    return hmac.new(_key_bytes(key), attestation_json.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(attestation_json: str, signature: str, key: Optional[Any] = None) -> bool:
    """True iff ``signature`` is a valid HMAC for ``attestation_json``."""
    expected = sign(attestation_json, key)
    return hmac.compare_digest(expected, signature)


def entry_hash(attestation_json: str, signature: str) -> str:
    """Chain hash for one entry; the next entry's ``prev_hash`` points here."""
    return _sha256_hex(attestation_json + "." + signature)


# ----- digests over the tool call and the displayed info -----------------

def tool_call_digest(context: Dict[str, Any]) -> str:
    """SHA-256 over the tool call in question (name + visible call history).

    We digest rather than store raw args: args may be large or sensitive, but a
    digest still binds the receipt to exactly which call was decided on.
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
) -> Dict[str, Any]:
    """Assemble the (unsigned) attestation object from a decided interrupt."""
    ctx = interrupt_record.get("context") or {}
    return {
        "version": ATTESTATION_VERSION,
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
        )
        attestation_json = canonical_json(attestation)
        signature = sign(attestation_json)
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


# ----- chain verification -------------------------------------------------

def verify_chain(records: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Check a seq-ordered list of attestation rows for integrity.

    Detects: a bad/forged signature, an altered field (signature no longer
    matches), a broken link (prev_hash mismatch), and a deleted entry (a gap in
    the consecutive sequence numbers). Returns (ok, error_message).
    """
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for rec in records:
        seq = rec["seq"]
        att_json = rec["attestation_json"]
        signature = rec["signature"]

        if seq != expected_seq:
            return False, f"non-consecutive sequence at seq={seq} (expected {expected_seq}) — entry deleted?"

        try:
            embedded_seq = json.loads(att_json).get("seq")
        except json.JSONDecodeError:
            return False, f"unparseable attestation at seq={seq}"
        if embedded_seq != seq:
            return False, f"seq mismatch at seq={seq}: signed body says {embedded_seq}"

        if not verify_signature(att_json, signature):
            return False, f"invalid signature at seq={seq} — entry altered"

        embedded_prev = json.loads(att_json).get("prev_hash")
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
    if SIGNING_KEY_FROM_ENV:
        lines.append(f"  Attestation signing key: from ${SIGNING_KEY_ENV}")
    else:
        lines.append("  Attestation signing key: generated — set to persist verifiability:")
        lines.append(f"      {SIGNING_KEY_ENV}={SIGNING_KEY.decode('utf-8')}")
    lines.append("  Decisions now produce signed receipts at /attestations.")
    lines.append("=" * 66)
    return "\n".join(lines)
