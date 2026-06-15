"""FastAPI backend for AgentBrake remote-mode validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from agentbrake import __version__

from . import security, store

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    store.init_db()
    # Secrets go to the server's OWN console only — never to the SDK/agent.
    print(security.startup_banner(), file=sys.stderr, flush=True)
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
    calls = []
    run_state = ctx.get("run_state") or {}
    if isinstance(run_state, dict):
        calls = run_state.get("calls") or []

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
    new_status = store.decide_interrupt(interrupt_id, payload.decision)
    if new_status is None:
        raise HTTPException(status_code=404, detail="interrupt not found")
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
