"""FastAPI backend for AgentBrake remote-mode validation."""

from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from agentbrake import __version__

from . import attest, security, store

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    store.init_db()
    # Secrets + signing key go to the server's OWN console only — never the SDK.
    print(security.startup_banner(), file=sys.stderr, flush=True)
    print(attest.signing_banner(), file=sys.stderr, flush=True)
    yield


app = FastAPI(title="AgentBrake", version=__version__, lifespan=_lifespan)


# ----- Request / response models -----------------------------------------

class CreateInterruptIn(BaseModel):
    run_id: str
    reason: str = Field(..., description="LOOP | BUDGET | ESCALATION")
    context: Dict[str, Any] = Field(default_factory=dict)


class CreateInterruptOut(BaseModel):
    interrupt_id: str
    validation_url: str


class DecideIn(BaseModel):
    decision: str = Field(..., description="approve | kill")
    args_digest: Optional[str] = Field(
        None,
        description=(
            "Digest of the pending call the approver was shown. Required to "
            "approve an interrupt whose context carries one; it binds the "
            "decision to the exact action displayed."
        ),
    )


class StatusOut(BaseModel):
    status: str


# ----- Routes ------------------------------------------------------------

@app.post(
    "/interrupts",
    response_model=CreateInterruptOut,
    dependencies=[Depends(security.require_sdk_secret)],
)
def create_interrupt(payload: CreateInterruptIn, request: Request) -> CreateInterruptOut:
    interrupt_id = store.create_interrupt(
        run_id=payload.run_id,
        reason=payload.reason,
        context=payload.context,
    )
    base = str(request.base_url).rstrip("/")
    return CreateInterruptOut(
        interrupt_id=interrupt_id,
        validation_url=f"{base}/interrupts/{interrupt_id}",
    )


def _format_cost(value: float) -> str:
    """Display cost in a human-readable form."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "$0.00"
    if v <= 0:
        return "$0.00"
    if v < 0.01:
        return "< $0.01"
    return f"${v:.2f}"


def _tool_label(ctx: Dict[str, Any]) -> str:
    """SDK sends `tool`; accept `tool_name` as a fallback for hand-crafted POSTs."""
    return ctx.get("tool") or ctx.get("tool_name") or "—"


@app.get("/interrupts/{interrupt_id}", response_class=HTMLResponse)
def view_interrupt(interrupt_id: str, request: Request) -> HTMLResponse:
    record = store.get_interrupt(interrupt_id)
    if record is None:
        raise HTTPException(status_code=404, detail="interrupt not found")

    ctx = record["context"] or {}
    calls: List[Dict[str, Any]] = []
    run_state = ctx.get("run_state") or {}
    if isinstance(run_state, dict):
        calls = run_state.get("calls") or []

    pending = ctx.get("pending_call") or {}

    return TEMPLATES.TemplateResponse(
        request,
        "validate.html",
        {
            "record": record,
            "context": ctx,
            "context_json": json.dumps(ctx, indent=2, default=str),
            "calls": calls,
            "tool_label": _tool_label(ctx),
            "cost_label": _format_cost(ctx.get("total_cost_usd", 0.0)),
            # The action awaiting a decision, shown in full. The digest is
            # echoed back on approve so the server can prove the approver saw
            # these exact arguments.
            "pending": pending,
            "pending_args_json": (
                json.dumps(pending.get("args", {}), indent=2, default=str)
                if pending
                else None
            ),
            "pending_digest": pending.get("args_digest"),
        },
    )


@app.post(
    "/interrupts/{interrupt_id}/decide",
    response_model=StatusOut,
    dependencies=[Depends(security.require_approver_secret)],
)
def decide(interrupt_id: str, payload: DecideIn) -> StatusOut:
    if payload.decision not in {"approve", "kill"}:
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'kill'")

    # Bind the approval to the action. The approver echoes the digest of the
    # pending call their page displayed; if it does not match the one stored
    # with the interrupt, they were looking at something other than what would
    # execute, and the approval means nothing. A `kill` needs no digest —
    # stopping is safe under every reading of the request.
    if payload.decision == "approve":
        existing = store.get_interrupt(interrupt_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="interrupt not found")
        expected = ((existing["context"] or {}).get("pending_call") or {}).get(
            "args_digest"
        )
        if expected is not None and payload.args_digest != expected:
            raise HTTPException(
                status_code=409,
                detail=(
                    "args_digest does not match the pending call; approval must "
                    "be bound to the action displayed. Reload the interrupt."
                ),
            )

    result = store.decide_interrupt(interrupt_id, payload.decision)
    if result is None:
        raise HTTPException(status_code=404, detail="interrupt not found")
    new_status, changed = result
    if changed:
        # A human just decided: mint the signed, chained receipt. Re-read the
        # interrupt so the attestation captures the persisted decided_at.
        decided = store.get_interrupt(interrupt_id)
        if decided is not None:
            attest.record_decision(decided, payload.decision)
    return StatusOut(status=new_status)


@app.get(
    "/interrupts/{interrupt_id}/status",
    response_model=StatusOut,
    dependencies=[Depends(security.require_sdk_secret)],
)
def get_status(interrupt_id: str) -> StatusOut:
    record = store.get_interrupt(interrupt_id)
    if record is None:
        raise HTTPException(status_code=404, detail="interrupt not found")
    return StatusOut(status=record["status"])


# ----- Attestations (verifiable receipts) --------------------------------
#
# These read-only endpoints are intentionally unauthenticated: a receipt is a
# proof meant to be independently verifiable, and it stores only digests of the
# tool call / displayed info, never raw args. The `signature_valid` flag is the
# server checking itself — a third party should not take its word for it, but
# run `agentbrake verify` on an export bundle with only the public key.

def _attestation_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """Shape a stored attestation row into an API response with a verify flag."""
    return {
        "seq": record["seq"],
        "interrupt_id": record["interrupt_id"],
        "attestation": record["attestation"],
        "signature": record["signature"],
        "prev_hash": record["prev_hash"],
        "entry_hash": record["entry_hash"],
        "signature_valid": attest.verify_record(record),
    }


@app.get("/attestations/verify")
def verify_attestation_chain() -> Dict[str, Any]:
    """Verify the integrity of the entire attestation chain."""
    chain = store.get_attestation_chain()
    ok, error = attest.verify_chain(chain)
    return {"ok": ok, "count": len(chain), "error": error}


@app.get("/attestations/export")
def export_attestation_chain() -> Dict[str, Any]:
    """Self-contained export bundle: entries + public key + signed chain head.

    This is what an operator hands to an auditor. Verification happens on the
    auditor's machine with `agentbrake verify` — offline, public key only —
    so the verdict does not rest on trusting this server.
    """
    from agentbrake import export as export_mod

    chain = store.get_attestation_chain()
    return export_mod.build_export(chain, signer=attest.SIGNER)


@app.get("/attestations")
def list_attestations() -> Dict[str, Any]:
    """Return the full attestation chain plus a chain-integrity verdict."""
    chain = store.get_attestation_chain()
    ok, error = attest.verify_chain(chain)
    return {
        "count": len(chain),
        "verified": ok,
        "error": error,
        "chain": [_attestation_view(r) for r in chain],
    }


@app.get("/attestations/{interrupt_id}")
def get_attestation(interrupt_id: str) -> Dict[str, Any]:
    """Return the signed attestation (receipt) for one interrupt."""
    record = store.get_attestation(interrupt_id)
    if record is None:
        raise HTTPException(status_code=404, detail="attestation not found")
    return _attestation_view(record)
