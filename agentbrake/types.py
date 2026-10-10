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
    DELEGATION = "delegation"


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
    cost_usd_micro: int = 0  # cost in micro-dollars (1,000,000 µ$ = 1 USD)
    # True when cost_usd is AgentBrake's flat per-call placeholder (guard()),
    # not a price derived from the call itself (e.g. token usage).
    cost_estimated: bool = False
    outcome: str = "pending"  # pending -> ok | error
    error: Optional[str] = None  # repr of the exception when outcome == "error"

    def __init__(self, **data):
        # Backward compatibility: accept cost_usd (float) and convert to micro-dollars
        if 'cost_usd' in data and 'cost_usd_micro' not in data:
            if isinstance(data['cost_usd'], float):
                data['cost_usd_micro'] = int(round(data.pop('cost_usd') * 1_000_000))
        super().__init__(**data)

    @property
    def cost_usd(self) -> float:
        """Convenience property: micro-dollars as USD float."""
        return self.cost_usd_micro / 1_000_000

    @cost_usd.setter
    def cost_usd(self, value: float) -> None:
        """Convenience setter: USD float to micro-dollars."""
        self.cost_usd_micro = int(round(value * 1_000_000))


class RunState(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    total_cost_usd_micro: int = 0  # cumulative cost in micro-dollars
    calls: List[ToolCall] = Field(default_factory=list)
    status: str = "running"
    taints: List[TaintMark] = Field(default_factory=list)

    def __init__(self, **data):
        # Backward compatibility: accept total_cost_usd (float) and convert to micro-dollars
        if 'total_cost_usd' in data and 'total_cost_usd_micro' not in data:
            if isinstance(data['total_cost_usd'], float):
                data['total_cost_usd_micro'] = int(round(data.pop('total_cost_usd') * 1_000_000))
        super().__init__(**data)

    @property
    def total_cost_usd(self) -> float:
        """Convenience property: micro-dollars as USD float."""
        return self.total_cost_usd_micro / 1_000_000

    @total_cost_usd.setter
    def total_cost_usd(self, value: float) -> None:
        """Convenience setter: USD float to micro-dollars."""
        self.total_cost_usd_micro = int(round(value * 1_000_000))

    @property
    def cost_is_estimate(self) -> bool:
        """True when any part of total_cost_usd is the flat per-call placeholder.

        Guarded tool calls are charged a fixed $0.01 each so that budget_usd
        works out of the box; that is a call-count proxy, not money spent.
        Only spend fed in from real usage (e.g. the CometAPI provider) is
        priced. Display total_cost_usd as an *estimate* whenever this is True.
        """
        return any(c.cost_estimated for c in self.calls)

    def append(self, call: ToolCall) -> None:
        self.calls.append(call)
        self.total_cost_usd_micro += call.cost_usd_micro

    def taint_labels(self) -> set:
        """The set of taint labels currently active in this run."""
        return {t.label for t in self.taints}


class AgentBrakeInterrupt(Exception):
    """Raised when a detector trips on a tool call.

    ``str(e)`` is one readable line — reason, tool, run_id — because it ends up
    in logs and, very often, in the tool result handed back to the model. The
    full detail stays on the exception: ``e.context`` (run state, pending call,
    flow/delegation explanation) and ``e.receipt`` (the signed receipt summary,
    when one was minted).
    """

    def __init__(self, reason: InterruptReason, context: Optional[Dict[str, Any]] = None):
        self.reason = reason
        self.context = context or {}
        super().__init__(self._summary())

    @property
    def tool(self) -> Optional[str]:
        return self.context.get("tool") or self.context.get("tool_name")

    @property
    def run_id(self) -> Optional[str]:
        return self.context.get("run_id")

    @property
    def receipt(self) -> Optional[Dict[str, Any]]:
        return self.context.get("receipt")

    def _summary(self) -> str:
        parts = [f"AgentBrake interrupt: {self.reason.value}"]
        if self.tool:
            # The tool name is model-chosen (an escalation is, by definition,
            # a name we did not expect): repr() escapes any newline so the
            # message stays one line, and the cap keeps it readable.
            name = str(self.tool)
            if len(name) > 80:
                name = name[:77] + "..."
            parts.append(f"on tool {name!r}")
        if self.run_id:
            parts.append(f"(run_id={self.run_id})")
        return " ".join(parts)

    def __reduce__(self):
        # Exception pickles as cls(*self.args), and args holds only the summary
        # line; rebuild from the real constructor arguments instead.
        return (type(self), (self.reason, self.context))
