"""Core data models for AgentBrake."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class InterruptReason(str, Enum):
    LOOP = "loop"
    BUDGET = "budget"
    ESCALATION = "escalation"
    TIMEOUT = "timeout"
    FLOW = "flow"


class TaintMark(BaseModel):
    """A taint label introduced into a run by a source tool.

    Provenance is kept so a flow violation can name *which* call let the taint
    in (e.g. "untrusted entered at call #2 via read_webpage"). This detail is
    what makes a flow-block receipt auditable rather than just a boolean.
    """

    label: str
    source_tool: str
    call_index: int


class ToolCall(BaseModel):
    name: str
    args: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cost_usd: float = 0.0
    outcome: str = "pending"  # pending -> ok | error
    error: Optional[str] = None  # repr of the exception when outcome == "error"


class RunState(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    total_cost_usd: float = 0.0
    calls: List[ToolCall] = Field(default_factory=list)
    status: str = "running"
    taints: List[TaintMark] = Field(default_factory=list)

    def append(self, call: ToolCall) -> None:
        self.calls.append(call)
        self.total_cost_usd += call.cost_usd

    def taint_labels(self) -> set:
        """The set of taint labels currently active in this run."""
        return {t.label for t in self.taints}


class AgentBrakeInterrupt(Exception):
    """Raised when a detector trips on a tool call."""

    def __init__(self, reason: InterruptReason, context: Optional[Dict[str, Any]] = None):
        self.reason = reason
        self.context = context or {}
        super().__init__(f"AgentBrake interrupt: {reason.value} | context={self.context}")
