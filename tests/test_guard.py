"""Tests for per-run state isolation (Run / run / init) and failed-call recording."""

from __future__ import annotations

import threading

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason


@pytest.fixture(autouse=True)
def _isolate_default_run():
    """Each test starts and ends with no process-wide default run."""
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    if args.get("boom"):
        raise RuntimeError("tool failed")
    return f"{name}-ok"


# --- FIX 1: per-run state isolation ----------------------------------------

def test_budget_exhaustion_does_not_leak_across_runs():
    with agentbrake.run(allowed_tools=["t"], budget_usd=0.015) as r1:
        assert dispatch("t", {"q": 1}) == "t-ok"
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {"q": 2})  # projected 0.02 > 0.015
        assert ei.value.reason is InterruptReason.BUDGET

    # A fresh run gets a fresh budget — the previous failure must not poison it.
    with agentbrake.run(allowed_tools=["t"], budget_usd=0.015) as r2:
        assert dispatch("t", {"q": 3}) == "t-ok"

    assert r1.state.run_id != r2.state.run_id
    assert r1.state.status == "interrupted"


def test_init_resets_state_on_each_call():
    agentbrake.init(allowed_tools=["t"], budget_usd=0.01)
    assert dispatch("t", {"q": 1}) == "t-ok"
    with pytest.raises(AgentBrakeInterrupt):
        dispatch("t", {"q": 2})

    agentbrake.init(allowed_tools=["t"], budget_usd=0.01)
    assert dispatch("t", {"q": 1}) == "t-ok"


def test_run_inherits_defaults_from_init():
    agentbrake.init(allowed_tools=["t"], budget_usd=10.0)
    with agentbrake.run(budget_usd=0.01):
        assert dispatch("t", {}) == "t-ok"  # allowlist inherited from init()
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("u", {})
        assert ei.value.reason is InterruptReason.ESCALATION


def test_exiting_run_restores_default_run():
    agentbrake.init(allowed_tools=["outer"], budget_usd=1.0)
    with agentbrake.run(allowed_tools=["inner"], budget_usd=1.0) as r:
        assert dispatch("inner", {}) == "inner-ok"
        assert agentbrake.current_run() is r

    assert agentbrake.current_run() is agentbrake._default_run
    assert dispatch("outer", {}) == "outer-ok"
    with pytest.raises(AgentBrakeInterrupt) as ei:
        dispatch("inner", {})  # inner allowlist is gone with its run
    assert ei.value.reason is InterruptReason.ESCALATION


def test_runs_are_isolated_across_threads():
    results: dict[str, float] = {}

    def worker(key: str, n_calls: int) -> None:
        with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
            for i in range(n_calls):
                dispatch("t", {"i": i})
            results[key] = r.state.total_cost_usd

    threads = [
        threading.Thread(target=worker, args=("a", 3)),
        threading.Thread(target=worker, args=("b", 5)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results["a"] == pytest.approx(0.03)
    assert results["b"] == pytest.approx(0.05)


def test_guard_without_init_or_run_raises():
    with pytest.raises(RuntimeError, match="no active run"):
        dispatch("t", {})


def test_run_status_lifecycle():
    with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
        dispatch("t", {})
    assert r.state.status == "completed"

    with pytest.raises(ValueError):
        with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r2:
            raise ValueError("user code blew up")
    assert r2.state.status == "failed"


def test_run_rejects_invalid_mode():
    with pytest.raises(ValueError):
        agentbrake.run(mode="telepathy")


# --- FIX 2: failed calls are recorded ---------------------------------------

def test_failed_call_is_recorded_with_error_outcome():
    with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
        with pytest.raises(RuntimeError):
            dispatch("t", {"boom": True})

        assert len(r.state.calls) == 1
        call = r.state.calls[0]
        assert call.outcome == "error"
        assert "tool failed" in (call.error or "")
        assert r.state.total_cost_usd == pytest.approx(0.01)


def test_successful_call_is_recorded_with_ok_outcome():
    with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
        dispatch("t", {})
        assert len(r.state.calls) == 1
        assert r.state.calls[0].outcome == "ok"
        assert r.state.calls[0].error is None


def test_repeated_failing_call_trips_loop_detector():
    with agentbrake.run(allowed_tools=["t"], budget_usd=10.0) as r:
        for _ in range(2):
            with pytest.raises(RuntimeError):
                dispatch("t", {"boom": True})

        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {"boom": True})
        assert ei.value.reason is InterruptReason.LOOP
        # The third attempt was intercepted before execution: only the two
        # real (failed) attempts are in the history.
        assert len(r.state.calls) == 2
        assert all(c.outcome == "error" for c in r.state.calls)


def test_failed_calls_count_toward_budget():
    with agentbrake.run(allowed_tools=["t"], budget_usd=0.02):
        # Distinct args keep the loop detector quiet — budget must trip first.
        with pytest.raises(RuntimeError):
            dispatch("t", {"boom": True, "i": 1})
        with pytest.raises(RuntimeError):
            dispatch("t", {"boom": True, "i": 2})

        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {"i": 3})
        assert ei.value.reason is InterruptReason.BUDGET
