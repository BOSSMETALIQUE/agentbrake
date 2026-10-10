"""USD amounts convert exactly or fail loudly — never silently become $0."""

from __future__ import annotations

import math
from decimal import Decimal
from fractions import Fraction

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason, RunState, ToolCall
from agentbrake.detectors import BudgetDetector
from agentbrake.server.main import _format_cost

BAD_TYPES = [True, False, "1.0", None, [1]]
BAD_VALUES = [math.nan, math.inf, -math.inf, -1, -0.01, Decimal("NaN"), Decimal("Infinity"), Decimal("-1")]


@pytest.fixture(autouse=True)
def _isolate():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@pytest.mark.parametrize(
    "value, micro",
    [
        (1, 1_000_000),
        (0, 0),
        (2.5, 2_500_000),
        (Decimal("0.000001"), 1),
        (Decimal("3"), 3_000_000),
        (Fraction(1, 4), 250_000),
    ],
)
def test_toolcall_accepts_int_float_decimal(value, micro):
    assert ToolCall(name="t", cost_usd=value).cost_usd_micro == micro


def test_int_cost_is_not_dropped():
    # The 0.3.4 bypass: ints were silently ignored and the cost became 0.0.
    assert ToolCall(name="t", cost_usd=1).cost_usd == 1.0
    assert RunState(total_cost_usd=2).total_cost_usd == 2.0


@pytest.mark.parametrize("value", BAD_TYPES)
def test_toolcall_rejects_non_numbers(value):
    with pytest.raises(TypeError, match="cost_usd must be a number"):
        ToolCall(name="t", cost_usd=value)


@pytest.mark.parametrize("value", BAD_VALUES)
def test_toolcall_rejects_nan_inf_negative(value):
    with pytest.raises(ValueError, match="cost_usd must be"):
        ToolCall(name="t", cost_usd=value)


@pytest.mark.parametrize("value", BAD_TYPES)
def test_runstate_rejects_non_numbers(value):
    with pytest.raises(TypeError, match="total_cost_usd must be a number"):
        RunState(total_cost_usd=value)


@pytest.mark.parametrize("value", BAD_VALUES)
def test_runstate_rejects_nan_inf_negative(value):
    with pytest.raises(ValueError, match="total_cost_usd must be"):
        RunState(total_cost_usd=value)


def test_setters_validate_too():
    call = ToolCall(name="t")
    call.cost_usd = 3
    assert call.cost_usd_micro == 3_000_000
    with pytest.raises(TypeError):
        call.cost_usd = True
    with pytest.raises(ValueError):
        call.cost_usd = math.nan

    state = RunState()
    state.total_cost_usd = Decimal("1.5")
    assert state.total_cost_usd_micro == 1_500_000
    with pytest.raises(ValueError):
        state.total_cost_usd = -2


def test_negative_micro_rejected():
    with pytest.raises(ValueError):
        ToolCall(name="t", cost_usd_micro=-1)
    with pytest.raises(ValueError):
        RunState(total_cost_usd_micro=-1)


def test_alias_and_micro_together_is_ambiguous():
    with pytest.raises(ValueError, match="not both"):
        ToolCall(name="t", cost_usd=1, cost_usd_micro=5)


@pytest.mark.parametrize("budget", [True, "5", math.nan, math.inf, -1])
def test_budget_detector_rejects_bad_budget(budget):
    with pytest.raises((TypeError, ValueError), match="budget_usd"):
        BudgetDetector(budget)


def test_run_rejects_nan_budget():
    # A NaN budget compares False to every total and would never trip.
    with pytest.raises(ValueError, match="budget_usd"):
        agentbrake.run(budget_usd=math.nan)


def test_int_budget_and_int_cost_block():
    det = BudgetDetector(2)
    state = RunState(total_cost_usd=2)
    assert det.check(state, ToolCall(name="t", cost_usd=1)) is InterruptReason.BUDGET
    assert BudgetDetector(Decimal("3")).check(state, ToolCall(name="t", cost_usd=1)) is None


def test_integer_cost_trips_budget_end_to_end():
    with agentbrake.run(allowed_tools=["llm"], budget_usd=2) as r:
        # Real spend fed in as an integer, the way a provider wrapper would.
        r.state.append(ToolCall(name="llm", cost_usd=2))
        assert r.state.total_cost_usd == 2.0

        @agentbrake.guard()
        def dispatch(name, args):
            return "ok"

        with pytest.raises(AgentBrakeInterrupt) as exc:
            dispatch("llm", {})
        assert exc.value.reason is InterruptReason.BUDGET


@pytest.mark.parametrize(
    "value, label",
    [
        (0, "$0.00"),
        (None, "$0.00"),
        (2, "$2.00"),
        (0.001, "< $0.01"),
        (True, "invalid"),
        ("3", "invalid"),
        (math.nan, "invalid"),
        (math.inf, "invalid"),
        (-1.0, "invalid"),
    ],
)
def test_server_cost_label(value, label):
    assert _format_cost(value) == label
