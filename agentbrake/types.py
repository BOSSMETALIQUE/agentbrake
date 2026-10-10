"""Core data models for AgentBrake."""

from __future__ import annotations

import math
import numbers
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def check_usd(value: Any, field: str, hint: str = "") -> Any:
    """Return ``value`` if it is a usable USD amount, else raise.

    Accepts any real number (int, float, Fraction, numpy scalars) and Decimal.
    Rejects bool (``True`` is an int, but never a price), NaN and infinities
    (a NaN budget or cost compares False to everything, so a budget check
    would silently never fire) and negative amounts (a negative cost would
    credit the budget back). ``hint`` is appended to every error message.
    """
    suffix = f". {hint}" if hint else ""
    if isinstance(value, bool) or not isinstance(value, (numbers.Real, Decimal)):
        raise TypeError(
            f"{field} must be a number of US dollars (int, float or Decimal), "
            f"got {type(value).__name__}: {value!r}{suffix}"
        )
    finite = value.is_finite() if isinstance(value, Decimal) else math.isfinite(value)
    if not finite:
        raise ValueError(f"{field} must be a finite amount, got {value!r}{suffix}")
    if value < 0:
        raise ValueError(f"{field} must be >= 0, got {value!r}{suffix}")
    return value


def usd_to_micro(value: Any, field: str = "cost_usd") -> int:
    """Convert a USD amount to integer micro-dollars, validating it first."""
    return int(round(check_usd(value, field) * 1_000_000))


def _pop_usd_alias(data: Dict[str, Any], alias: str, micro_field: str) -> None:
    """Move the USD convenience kwarg (``cost_usd``) onto its micro field.

    Pydantic ignores unknown kwargs, so before 0.3.4 an alias this did not
    convert (e.g. an int) was silently dropped and the amount became 0.
    """
    if alias not in data:
        return
    if micro_field in data:
        raise ValueError(f"pass either {alias} or {micro_field}, not both")
    data[micro_field] = usd_to_micro(data.pop(alias), alias)


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
    cost_usd_micro: int = Field(default=0, ge=0)  # micro-dollars (1,000,000 µ$ = 1 USD)
    # True when cost_usd is AgentBrake's flat per-call placeholder (guard()),
    # not a price derived from the call itself (e.g. token usage).
    cost_estimated: bool = False
    outcome: str = "pending"  # pending -> ok | error
    error: Optional[str] = None  # repr of the exception when outcome == "error"

    def __init__(self, **data):
        # Convenience: accept cost_usd (int, float or Decimal) as micro-dollars.
        _pop_usd_alias(data, "cost_usd", "cost_usd_micro")
        super().__init__(**data)

    @property
    def cost_usd(self) -> float:
        """Convenience property: micro-dollars as USD float."""
        return self.cost_usd_micro / 1_000_000

    @cost_usd.setter
    def cost_usd(self, value: float) -> None:
        """Convenience setter: USD amount to micro-dollars."""
        self.cost_usd_micro = usd_to_micro(value, "cost_usd")


class RunState(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    total_cost_usd_micro: int = Field(default=0, ge=0)  # cumulative, micro-dollars
    calls: List[ToolCall] = Field(default_factory=list)
    status: str = "running"
    taints: List[TaintMark] = Field(default_factory=list)

    def __init__(self, **data):
        # Convenience: accept total_cost_usd (int, float or Decimal) as micro-dollars.
        _pop_usd_alias(data, "total_cost_usd", "total_cost_usd_micro")
        super().__init__(**data)

    @property
    def total_cost_usd(self) -> float:
        """Convenience property: micro-dollars as USD float."""
        return self.total_cost_usd_micro / 1_000_000

    @total_cost_usd.setter
    def total_cost_usd(self, value: float) -> None:
        """Convenience setter: USD amount to micro-dollars."""
        self.total_cost_usd_micro = usd_to_micro(value, "total_cost_usd")

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
        summary = " ".join(parts)
        budget = self.context.get("budget_usd")
        if (
            self.reason is InterruptReason.BUDGET
            and isinstance(budget, (int, float))
            and not isinstance(budget, bool)
            and budget == 0
        ):
            # A zero budget is almost always the unset default (init() with no
            # budget_usd), which blocks the very first guarded call. Say so.
            summary += (
                ": budget_usd is 0.0 (the default); set budget_usd=<amount> "
                "or budget_usd=agentbrake.UNLIMITED"
            )
        return summary

    def __reduce__(self):
        # Exception pickles as cls(*self.args), and args holds only the summary
        # line; rebuild from the real constructor arguments instead.
        return (type(self), (self.reason, self.context))
