"""In-process signed receipts for autonomous flow blocks.

The server mints a signed, hash-chained attestation every time a *human*
approves or kills an interrupt (see ``agentbrake.server.attest``). A flow block,
though, happens autonomously and in-process — usually in local mode, with no
server and no SQLite. This module brings the *same* cryptographic receipt to
that path so an automatic "I stopped a prompt-injection -> exfiltration attempt"
is just as provable as a human decision: a signed, tamper-evident record you can
hand to an auditor.

It reuses the server's primitives verbatim — ``canonical_json``, ``sign``,
``entry_hash`` and ``verify_chain`` from :mod:`agentbrake.server.attest` — so a
flow receipt and a human-decision receipt share one format, one signing key
(``AGENTBRAKE_SIGNING_KEY``) and one verifier. Only the *storage* differs: a
pluggable :class:`Ledger` instead of the server's SQLite chain.

Honest limitation: an in-process ledger is only as tamper-evident as where it
lives. The signature stops silent edits and the hash chain stops silent
deletions, but an attacker who can run code in the agent's process can drop the
whole ledger before it is persisted. For durable proof, point a run at a
:class:`JsonlLedger` on append-only storage, set a stable signing key, and ship
the lines off-box.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

from agentbrake.server import attest
from .types import RunState, ToolCall

# Re-export so callers verify receipts without importing the server package.
GENESIS_HASH = attest.GENESIS_HASH
RECEIPT_VERSION = attest.ATTESTATION_VERSION

# Serializes read-tail -> build -> sign -> append, mirroring the server's
# _CHAIN_LOCK: without it two threads blocking concurrently could both read
# the same tail and mint the same seq, forking the chain. One process-wide
# lock (rather than per-ledger) keeps the Ledger protocol minimal; minting is
# rare enough that the contention is irrelevant.
_MINT_LOCK = threading.Lock()


# ----- ledgers ------------------------------------------------------------

class Ledger(Protocol):
    """Append-only store of chained receipt rows, ordered by ``seq``."""

    def tail(self) -> Optional[Dict[str, Any]]: ...
    def append(self, row: Dict[str, Any]) -> None: ...
    def all(self) -> List[Dict[str, Any]]: ...


class InMemoryLedger:
    """Per-run, in-process chain. Lost when the process exits."""

    def __init__(self) -> None:
        self._rows: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def tail(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._rows[-1]) if self._rows else None

    def append(self, row: Dict[str, Any]) -> None:
        with self._lock:
            self._rows.append(dict(row))

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._rows]


class JsonlLedger:
    """File-backed chain: one JSON object per line, appended in order.

    Durable across restarts, so receipts stay verifiable. Concurrency is
    serialized within a process by a lock; cross-process appends to the same
    file are not coordinated, so give each writer its own file.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()

    def _read(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    def tail(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            rows = self._read()
            return rows[-1] if rows else None

    def append(self, row: Dict[str, Any]) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._read()


# ----- digests & building -------------------------------------------------

def _digest(obj: Any) -> str:
    """``sha256:<hex>`` over the canonical JSON of ``obj`` (server-compatible)."""
    body = attest.canonical_json(obj)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def sink_call_digest(call: ToolCall) -> str:
    """Bind the receipt to exactly which sink call was blocked, without raw args."""
    return _digest({"tool": call.name, "args": call.args})


def build_flow_attestation(
    *,
    seq: int,
    prev_hash: str,
    run_id: Optional[str],
    sink_call: ToolCall,
    flow: Dict[str, Any],
    chain_id: str,
    agent_id: Optional[str] = None,
    blocked_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble the (unsigned) attestation for one autonomous flow block.

    Mirrors the human-decision attestation but records ``decision="block"`` and
    a ``flow`` payload (offending sink, the taints it violated, and the call
    that introduced each taint).
    """
    return {
        "version": RECEIPT_VERSION,
        "alg": attest.SIGNER.alg,
        "key_id": attest.SIGNER.key_id,
        "chain_id": chain_id,
        "seq": seq,
        "kind": "flow_block",
        "run_id": run_id,
        "agent_id": agent_id,
        "decision": "block",
        "reason": "flow",
        "tool": sink_call.name,
        "tool_args_digest": sink_call_digest(sink_call),
        "blocked_at": blocked_at or datetime.now(timezone.utc).isoformat(),
        "flow": flow,
        "info_digest": _digest(flow),
        "prev_hash": prev_hash,
    }


def _seal_and_append(ledger: Ledger, build) -> Dict[str, Any]:
    """Common mint core: read tail, build, sign, chain, append — atomically.

    ``build(seq, prev_hash, chain_id)`` returns the (unsigned) attestation.
    Serialized under the mint lock so concurrent mints cannot fork the chain.
    """
    with _MINT_LOCK:
        tail = ledger.tail()
        seq = (tail["seq"] + 1) if tail else 1
        prev_hash = tail["entry_hash"] if tail else GENESIS_HASH

        attestation = build(seq, prev_hash, attest.chain_id_from_tail(tail))
        attestation_json = attest.canonical_json(attestation, strict=True)
        signature = attest.sign_body(attestation_json)
        e_hash = attest.entry_hash(attestation_json, signature)

        row = {
            "seq": seq,
            "run_id": attestation.get("run_id"),
            "attestation": attestation,
            "attestation_json": attestation_json,
            "signature": signature,
            "prev_hash": prev_hash,
            "entry_hash": e_hash,
        }
        ledger.append(row)
    return row


def mint_flow_receipt(
    ledger: Ledger,
    *,
    run_state: RunState,
    sink_call: ToolCall,
    flow: Dict[str, Any],
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build, sign, chain and persist the receipt for one flow block.

    Signs with the shared ``attest.SIGNER`` so the receipt verifies through
    the same path as a human-decision attestation. Returns the stored row.
    """
    return _seal_and_append(
        ledger,
        lambda seq, prev_hash, chain_id: build_flow_attestation(
            seq=seq,
            prev_hash=prev_hash,
            run_id=run_state.run_id,
            sink_call=sink_call,
            flow=flow,
            chain_id=chain_id,
            agent_id=agent_id,
        ),
    )


def build_delegation_attestation(
    *,
    seq: int,
    prev_hash: str,
    chain_id: str,
    kind: str,
    decision: str,
    run_id: Optional[str],
    delegation: Dict[str, Any],
    tool: Optional[str] = None,
    agent_id: Optional[str] = None,
    recorded_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble the (unsigned) attestation for one delegation decision.

    ``kind`` is one of ``delegation_grant`` / ``delegation_accept`` /
    ``delegation_reject`` / ``delegation_block``. The ``delegation`` payload
    embeds the full signed token links, so an auditor holding only the
    receipt chain can re-verify the tokens themselves — the receipt does not
    merely assert that a delegation existed, it carries the proof.
    """
    return {
        "version": RECEIPT_VERSION,
        "alg": attest.SIGNER.alg,
        "key_id": attest.SIGNER.key_id,
        "chain_id": chain_id,
        "seq": seq,
        "kind": kind,
        "run_id": run_id,
        "agent_id": agent_id,
        "decision": decision,
        "reason": "delegation",
        "tool": tool,
        "recorded_at": recorded_at or datetime.now(timezone.utc).isoformat(),
        "delegation": delegation,
        "info_digest": _digest(delegation),
        "prev_hash": prev_hash,
    }


def mint_delegation_receipt(
    ledger: Ledger,
    *,
    kind: str,
    decision: str,
    run_id: Optional[str],
    delegation: Dict[str, Any],
    tool: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build, sign, chain and persist the receipt for one delegation decision."""
    return _seal_and_append(
        ledger,
        lambda seq, prev_hash, chain_id: build_delegation_attestation(
            seq=seq,
            prev_hash=prev_hash,
            chain_id=chain_id,
            kind=kind,
            decision=decision,
            run_id=run_id,
            delegation=delegation,
            tool=tool,
            agent_id=agent_id,
        ),
    )


def receipt_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    """The small, proof-bearing slice of a receipt to attach to an interrupt."""
    return {
        "seq": row["seq"],
        "signature": row["signature"],
        "prev_hash": row["prev_hash"],
        "entry_hash": row["entry_hash"],
        "attestation": row["attestation"],
    }


def verify_chain(
    rows: List[Dict[str, Any]],
    *,
    public_keys: Optional[Dict[str, str]] = None,
    hmac_key: Optional[bytes] = None,
) -> Tuple[bool, Optional[str]]:
    """Verify a receipt chain with the server's verifier (signatures + links).

    With no arguments this is a self-check under the process's own signer. To
    verify as a third party, pass ``public_keys`` ({key_id: public_key_hex}) —
    no private material needed.
    """
    return attest.verify_chain(rows, public_keys=public_keys, hmac_key=hmac_key)
