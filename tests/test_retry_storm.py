"""Tests for RetryStormDetector (unit + wired into guard) and cost_from_tokens."""

from __future__ import annotations

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason
from agentbrake.detectors import RetryStormDetector, cost_from_tokens
from agentbrake.types import RunState, ToolCall


def _call(name: str = "search", args: dict | None = None, outcome: str = "pending") -> ToolCall:
    c = ToolCall(name=name, args=args or {})
    c.outcome = outcome
    return c


# --- RetryStormDetector: unit --------------------------------------------

def test_flags_storm_of_varied_args_same_tool():
    """Same tool, different (non-numeric) args, no success signal -> storm."""
    detector = RetryStormDetector(max_calls_per_tool=3, window=10)
    state = RunState()
    state.append(_call(args={"q": "a"}))
    state.append(_call(args={"q": "b"}))
    # Third call to the same tool with yet another arg: LoopDetector (exact hash)
    # would miss this, but the storm detector counts by tool name.
    assert detector.check(state, _call(args={"q": "c"})) is InterruptReason.LOOP


def test_flags_alternating_loop():
    """search, read, search, read, search ... is a loop LoopDetector misses."""
    detector = RetryStormDetector(max_calls_per_tool=3, window=10)
    state = RunState()
    state.append(_call(name="search", args={"q": "a"}))
    state.append(_call(name="read", args={"path": "x"}))
    state.append(_call(name="search", args={"q": "b"}))
    state.append(_call(name="read", args={"path": "y"}))
    assert detector.check(state, _call(name="search", args={"q": "c"})) is InterruptReason.LOOP


def test_allows_under_threshold():
    detector = RetryStormDetector(max_calls_per_tool=3, window=10)
    state = RunState()
    state.append(_call(args={"q": "a"}))
    assert detector.check(state, _call(args={"q": "b"})) is None


def test_window_excludes_old_calls():
    """A same-tool call that has scrolled out of the window must not count."""
    detector = RetryStormDetector(max_calls_per_tool=2, window=2)
    state = RunState()
    state.append(_call(name="search", args={"q": "a"}))  # outside the window
    state.append(_call(name="read", args={"path": "x"}))
    assert detector.check(state, _call(name="search", args={"q": "b"})) is None


# --- progress awareness ---------------------------------------------------

def test_progress_aware_allows_numeric_pagination():
    detector = RetryStormDetector(max_calls_per_tool=3, window=10, progress_aware=True)
    state = RunState()
    state.append(_call(args={"page": 1}))
    state.append(_call(args={"page": 2}))
    assert detector.check(state, _call(args={"page": 3})) is None


def test_progress_unaware_flags_pagination():
    detector = RetryStormDetector(max_calls_per_tool=3, window=10, progress_aware=False)
    state = RunState()
    state.append(_call(args={"page": 1}))
    state.append(_call(args={"page": 2}))
    assert detector.check(state, _call(args={"page": 3})) is InterruptReason.LOOP


def test_progress_aware_allows_varied_succeeding_burst():
    """Distinct cursor calls that actually succeeded look like real work."""
    detector = RetryStormDetector(max_calls_per_tool=3, window=10, progress_aware=True)
    state = RunState()
    state.append(_call(args={"cursor": "aaa"}, outcome="ok"))
    state.append(_call(args={"cursor": "bbb"}, outcome="ok"))
    assert detector.check(state, _call(args={"cursor": "ccc"})) is None


def test_constructor_validates_bounds():
    with pytest.raises(ValueError):
        RetryStormDetector(max_calls_per_tool=1)
    with pytest.raises(ValueError):
        RetryStormDetector(max_calls_per_tool=5, window=3)


# --- RetryStormDetector: wired into guard ---------------------------------

@pytest.fixture(autouse=True)
def _isolate_default_run():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    if args.get("boom"):
        raise RuntimeError("tool failed")
    return f"{name}-ok"


def test_guard_trips_on_failing_retry_storm():
    """Varied args defeat the exact-hash LoopDetector; the storm detector
    (active by default) still stops the run."""
    with agentbrake.run(
        allowed_tools=["t"], budget_usd=10.0, retry_max_calls_per_tool=3
    ) as r:
        for i in ("a", "b"):
            with pytest.raises(RuntimeError):
                dispatch("t", {"x": i, "boom": True})

        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {"x": "c", "boom": True})
        assert ei.value.reason is InterruptReason.LOOP
        # The third attempt was intercepted before execution.
        assert len(r.state.calls) == 2


def test_guard_allows_legitimate_pagination_by_default():
    """Progress-aware storm detection must not stop a healthy page walk."""
    with agentbrake.run(allowed_tools=["t"], budget_usd=10.0, retry_max_calls_per_tool=3):
        for page in range(1, 7):
            assert dispatch("t", {"page": page}) == "t-ok"


def test_guard_storm_detection_can_be_loosened():
    """Raising the cap (and window) lets more same-tool calls through."""
    with agentbrake.run(
        allowed_tools=["t"],
        budget_usd=10.0,
        retry_max_calls_per_tool=12,
        retry_window=15,
    ):
        for i in range(10):
            with pytest.raises(RuntimeError):
                dispatch("t", {"x": i, "boom": True})  # 10 failing, varied -> still allowed


# --- cost_from_tokens -----------------------------------------------------

def test_cost_known_model():
    assert cost_from_tokens("gpt-4o", 1_000_000, 0) == pytest.approx(2.50)
    assert cost_from_tokens("gpt-4o", 0, 1_000_000) == pytest.approx(10.00)


def test_cost_unknown_model_uses_default_not_zero():
    # DEFAULT_PRICING = (5.00, 15.00); a typo must never look free.
    assert cost_from_tokens("totally-made-up", 1_000_000, 0) == pytest.approx(5.00)
    assert cost_from_tokens("totally-made-up", 0, 0) == pytest.approx(0.0)


def test_cost_mixed_tokens():
    expected = (1000 / 1_000_000) * 0.15 + (1000 / 1_000_000) * 0.60
    assert cost_from_tokens("gpt-4o-mini", 1000, 1000) == pytest.approx(expected)
