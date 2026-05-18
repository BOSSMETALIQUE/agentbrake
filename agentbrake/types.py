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


class ToolCall(BaseModel):
    name: str
    args: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cost_usd: float = 0.0


class RunState(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    total_cost_usd: float = 0.0
    calls: List[ToolCall] = Field(default_factory=list)
    status: str = "running"

    def append(self, call: ToolCall) -> None:
        self.calls.append(call)
        self.total_cost_usd += call.cost_usd


class AgentBrakeInterrupt(Exception):
    """Raised when a detector trips on a tool call."""

    def __init__(self, reason: InterruptReason, context: Optional[Dict[str, Any]] = None):
        self.reason = reason
        self.context = context or {}
        super().__init__(f"AgentBrake interrupt: {reason.value} | context={self.context}")
