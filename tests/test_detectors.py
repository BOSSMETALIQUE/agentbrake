"""Unit tests for the three detectors."""

from __future__ import annotations

from agentbrake.detectors import (
    BudgetDetector,
    EscalationDetector,
    LoopDetector,
    _structural_hash,
)
from agentbrake.types import InterruptReason, RunState, ToolCall


def _call(name: str = "search", args: dict | None = None, cost: float = 0.0) -> ToolCall:
    return ToolCall(name=name, args=args or {}, cost_usd=cost)


# --- LoopDetector ---------------------------------------------------------

def test_loop_detector_flags_third_identical_call():
    detector = LoopDetector(threshold=3)
    state = RunState()
    base_args = {"q": "hello", "k": 5}

    assert detector.check(state, _call(args=base_args)) is None
    state.append(_call(args=base_args))

    assert detector.check(state, _call(args=base_args)) is None
    state.append(_call(args=base_args))

    assert detector.check(state, _call(args=base_args)) is InterruptReason.LOOP


def test_loop_detector_ignores_when_args_differ():
    detector = LoopDetector(threshold=3)
    state = RunState()
    state.append(_call(args={"q": "a"}))
    state.append(_call(args={"q": "b"}))
    assert detector.check(state, _call(args={"q": "c"})) is None


def test_loop_detector_arg_order_insensitive():
    detector = LoopDetector(threshold=3)
    state = RunState()
    state.append(_call(args={"a": 1, "b": 2}))
    state.append(_call(args={"b": 2, "a": 1}))
    assert detector.check(state, _call(args={"a": 1, "b": 2})) is InterruptReason.LOOP


def test_structural_hash_normalizes_nested_args():
    """Nested dicts must hash identically regardless of key ordering."""
    c1 = _call(args={"outer": {"a": 1, "b": 2}, "z": [1, 2]})
    c2 = _call(args={"z": [1, 2], "outer": {"b": 2, "a": 1}})
    assert _structural_hash(c1) == _structural_hash(c2)


# --- BudgetDetector -------------------------------------------------------

def test_budget_detector_flags_when_exceeded():
    detector = BudgetDetector(budget_usd=1.0)
    state = RunState(total_cost_usd=0.95)
    assert detector.check(state, _call(cost=0.10)) is InterruptReason.BUDGET


def test_budget_detector_allows_under_budget():
    detector = BudgetDetector(budget_usd=1.0)
    state = RunState(total_cost_usd=0.50)
    assert detector.check(state, _call(cost=0.10)) is None


def test_budget_detector_allows_exact_budget():
    detector = BudgetDetector(budget_usd=1.0)
    state = RunState(total_cost_usd=0.90)
    assert detector.check(state, _call(cost=0.10)) is None


# --- EscalationDetector ---------------------------------------------------

def test_escalation_detector_flags_unknown_tool():
    detector = EscalationDetector(allowed_tools=["search"])
    assert detector.check(RunState(), _call(name="rm_rf")) is InterruptReason.ESCALATION


def test_escalation_detector_allows_known_tool():
    detector = EscalationDetector(allowed_tools=["search", "fetch"])
    assert detector.check(RunState(), _call(name="search")) is None
    assert detector.check(RunState(), _call(name="fetch")) is None
