"""Detectors that flag unsafe agent behavior on a per-call basis."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, List, Optional

from .types import InterruptReason, RunState, ToolCall


def _structural_hash(call: ToolCall) -> str:
    """SHA-256 of (tool_name, args) serialized as JSON with sorted keys."""
    payload = json.dumps(
        {"name": call.name, "args": call.args},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LoopDetector:
    """Flags when N consecutive calls share the same structural hash."""

    def __init__(self, threshold: int = 3):
        if threshold < 2:
            raise ValueError("threshold must be >= 2")
        self.threshold = threshold

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        target = _structural_hash(new_call)
        recent = run_state.calls[-(self.threshold - 1):]
        if len(recent) < self.threshold - 1:
            return None
        if all(_structural_hash(c) == target for c in recent):
            return InterruptReason.LOOP
        return None


class BudgetDetector:
    """Flags when projected total cost would exceed the configured budget."""

    def __init__(self, budget_usd: float):
        self.budget_usd = budget_usd

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        projected = run_state.total_cost_usd + new_call.cost_usd
        if projected > self.budget_usd:
            return InterruptReason.BUDGET
        return None


class EscalationDetector:
    """Flags when a tool call targets a name outside the allow-list."""

    def __init__(self, allowed_tools: Iterable[str]):
        self.allowed_tools: List[str] = list(allowed_tools)

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        if new_call.name not in self.allowed_tools:
            return InterruptReason.ESCALATION
        return None
