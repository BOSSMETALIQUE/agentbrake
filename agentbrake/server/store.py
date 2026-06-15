"""SQLite store for AgentBrake interrupts.

Thread-safe via per-call connections (SQLite handles concurrent readers fine
and FastAPI dependency injection scopes a fresh connection per request).
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4


def _default_db_path() -> Path:
    """CWD-relative by default; the AGENTBRAKE_DB env var overrides it.

    Must NOT live inside the installed package directory — site-packages may
    be read-only and is shared across projects.
    """
    env = os.environ.get("AGENTBRAKE_DB")
    if env:
        return Path(env).expanduser()
    return Path.cwd() / "agentbrake.db"


DEFAULT_DB_PATH = _default_db_path()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Create the interrupts and attestations tables if they don't exist."""
    path = db_path or DEFAULT_DB_PATH
    with _connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS interrupts (
                id          TEXT PRIMARY KEY,
                run_id      TEXT NOT NULL,
                reason      TEXT NOT NULL,
                context     TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TEXT NOT NULL,
                decided_at  TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attestations (
                seq          INTEGER PRIMARY KEY,
                interrupt_id TEXT NOT NULL,
                attestation  TEXT NOT NULL,
                signature    TEXT NOT NULL,
                prev_hash    TEXT NOT NULL,
                entry_hash   TEXT NOT NULL,
                created_at   TEXT NOT NULL
            )
            """
        )


def create_interrupt(
    run_id: str,
    reason: str,
    context: Dict[str, Any],
    db_path: Optional[Path] = None,
) -> str:
    """Insert a new pending interrupt. Returns the generated id."""
    path = db_path or DEFAULT_DB_PATH
    interrupt_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO interrupts (id, run_id, reason, context, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (interrupt_id, run_id, reason, json.dumps(context), now),
        )
    return interrupt_id


def get_interrupt(interrupt_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetch one interrupt by id, or None if missing."""
    path = db_path or DEFAULT_DB_PATH
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM interrupts WHERE id = ?", (interrupt_id,)
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["context"] = json.loads(record["context"])
    return record


def decide_interrupt(
    interrupt_id: str,
    decision: str,
    db_path: Optional[Path] = None,
) -> Optional[Tuple[str, bool]]:
    """Set status to 'approved' or 'killed'.

    Returns ``(status, changed)`` where ``changed`` is True only when THIS call
    transitioned the interrupt out of 'pending'. Returns None if the interrupt
    does not exist. The ``changed`` flag lets the caller attest exactly once,
    even if a decision is submitted twice.
    """
    if decision not in {"approve", "kill"}:
        raise ValueError("decision must be 'approve' or 'kill'")
    new_status = "approved" if decision == "approve" else "killed"
    path = db_path or DEFAULT_DB_PATH
    now = datetime.now(timezone.utc).isoformat()
    with _connect(path) as conn:
        cur = conn.execute(
            "UPDATE interrupts SET status = ?, decided_at = ? "
            "WHERE id = ? AND status = 'pending'",
            (new_status, now, interrupt_id),
        )
        if cur.rowcount == 0:
            # Either missing or already decided — report current state, no change.
            row = conn.execute(
                "SELECT status FROM interrupts WHERE id = ?", (interrupt_id,)
            ).fetchone()
            return (row["status"], False) if row else None
    return new_status, True


# ----- Attestations -------------------------------------------------------

def _row_to_attestation(row: sqlite3.Row) -> Dict[str, Any]:
    rec = dict(row)
    # Expose both the raw signed bytes (for verification) and the parsed object.
    rec["attestation_json"] = rec["attestation"]
    rec["attestation"] = json.loads(rec["attestation"])
    return rec


def get_chain_tail(db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Return the highest-seq attestation row, or None if the chain is empty."""
    path = db_path or DEFAULT_DB_PATH
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM attestations ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    return _row_to_attestation(row) if row else None


def insert_attestation(
    seq: int,
    interrupt_id: str,
    attestation_json: str,
    signature: str,
    prev_hash: str,
    entry_hash: str,
    db_path: Optional[Path] = None,
) -> None:
    """Persist one signed, chained attestation row."""
    path = db_path or DEFAULT_DB_PATH
    now = datetime.now(timezone.utc).isoformat()
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO attestations "
            "(seq, interrupt_id, attestation, signature, prev_hash, entry_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (seq, interrupt_id, attestation_json, signature, prev_hash, entry_hash, now),
        )


def get_attestation(
    interrupt_id: str, db_path: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """Return the attestation for one interrupt, or None."""
    path = db_path or DEFAULT_DB_PATH
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM attestations WHERE interrupt_id = ? ORDER BY seq DESC LIMIT 1",
            (interrupt_id,),
        ).fetchone()
    return _row_to_attestation(row) if row else None


def get_attestation_chain(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return all attestations ordered by sequence number (ascending)."""
    path = db_path or DEFAULT_DB_PATH
    with _connect(path) as conn:
        rows = conn.execute("SELECT * FROM attestations ORDER BY seq ASC").fetchall()
    return [_row_to_attestation(r) for r in rows]
