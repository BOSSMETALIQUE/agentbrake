"""Detectors that flag unsafe agent behavior on a per-call basis."""
from __future__ import annotations

import hashlib
import json
from typing import Dict, Iterable, List, Optional

from .types import InterruptReason, RunState, ToolCall


def _structural_hash(call: ToolCall) -> str:
    """SHA-256 of (tool_name, args) serialized as JSON with sorted keys."""
    payload = json.dumps(
        {"name": call.name, "args": call.args},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_number(value) -> bool:
    """True for int/float, but NOT bool (which is technically an int in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _has_monotonic_numeric_arg(calls: List[ToolCall]) -> bool:
    """Detect a numeric argument that strictly climbs or drops across the calls.

    This is the classic pagination signature: page=1, 2, 3 ... or offset=0, 10,
    20 ... A key only qualifies if it is present AND numeric in *every* call,
    and its values are strictly increasing or strictly decreasing. Needs at
    least 3 points so a single step isn't mistaken for a trend.
    """
    if len(calls) < 3:
        return False
    # keys that are numeric in the very first call are candidates
    candidate_keys = [k for k, v in calls[0].args.items() if _is_number(v)]
    for key in candidate_keys:
        series = []
        ok = True
        for c in calls:
            v = c.args.get(key, None)
            if not _is_number(v):
                ok = False
                break
            series.append(v)
        if not ok or len(series) < 3:
            continue
        strictly_up = all(b > a for a, b in zip(series, series[1:]))
        strictly_down = all(b < a for a, b in zip(series, series[1:]))
        if strictly_up or strictly_down:
            return True
    return False


def _looks_like_progress(prior_same_tool: List[ToolCall], new_call: ToolCall) -> bool:
    """Decide whether a burst of same-tool calls is healthy work, not a stuck loop.

    Two independent signals count as progress:

    1. A numeric argument that climbs/drops monotonically (page=1,2,3...).
       Works regardless of whether outcomes were recorded.

    2. The calls are nearly all distinct AND the ones that finished actually
       succeeded. This catches cursor-based pagination / legitimate iteration
       where there is no simple numeric key, but only when there is real
       evidence of success (outcome == "ok"). Pending/unknown outcomes do NOT
       count as success, so an untracked burst still trips the brake.
    """
    series = prior_same_tool + [new_call]

    # Signal 1: numeric pagination.
    if _has_monotonic_numeric_arg(series):
        return True

    # Signal 2: varied + actually succeeding.
    if len(prior_same_tool) >= 2:
        hashes = {_structural_hash(c) for c in series}
        distinct_ratio = len(hashes) / len(series)
        errors = sum(1 for c in prior_same_tool if c.outcome == "error")
        oks = sum(1 for c in prior_same_tool if c.outcome == "ok")
        if distinct_ratio >= 0.8 and errors == 0 and oks >= 2:
            return True

    return False


class LoopDetector:
    """Flags when N consecutive calls share the same structural hash.

    This catches *exact* repetition: the agent calling the same tool with the
    same arguments over and over (e.g. search("news") -> search("news") -> ...).
    For same-tool loops where only the arguments change, use RetryStormDetector.
    """

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


class RetryStormDetector:
    """Flags when the same tool is hammered too many times in a recent window.

    Unlike LoopDetector, this does NOT require the arguments to match, and does
    NOT require the calls to be consecutive. It catches failure modes that exact
    -hash loop detection misses:

      * retry storms      -> search("A"), search("B"), search("C"), ...
      * alternating loops -> search, read, search, read, search, ...

    It counts how many times `new_call.name` appears among the last `window`
    calls (including the new one). If that count reaches `max_calls_per_tool`,
    the run is flagged as a loop -- UNLESS the burst looks like real progress.

    Progress awareness (on by default) keeps legitimate pagination from tripping
    the brake: an agent walking through pages (page=1, 2, 3 ...) or iterating a
    cursor with successful calls is doing real work, not spinning. When
    `progress_aware` is True, such bursts are allowed through; the budget cap and
    the allow-list remain your hard stops. Set `progress_aware=False` to fall
    back to pure count-based behavior.

    Args:
        max_calls_per_tool: how many calls to the same tool are allowed inside
            the window before the brake trips. Must be >= 2.
        window: how many recent calls to look back over. Must be
            >= max_calls_per_tool. A larger window catches slower loops; a
            smaller one only catches tight bursts.
        progress_aware: when True (default), bursts that show monotonic numeric
            progress, or that are varied and succeeding, are not flagged.
    """

    def __init__(
        self,
        max_calls_per_tool: int = 5,
        window: int = 10,
        progress_aware: bool = True,
    ):
        if max_calls_per_tool < 2:
            raise ValueError("max_calls_per_tool must be >= 2")
        if window < max_calls_per_tool:
            raise ValueError("window must be >= max_calls_per_tool")
        self.max_calls_per_tool = max_calls_per_tool
        self.window = window
        self.progress_aware = progress_aware

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        recent = run_state.calls[-(self.window - 1):]
        prior_same_tool = [c for c in recent if c.name == new_call.name]
        # +1 for the new call we are about to make
        same_tool_count = len(prior_same_tool) + 1

        if same_tool_count < self.max_calls_per_tool:
            return None

        if self.progress_aware and _looks_like_progress(prior_same_tool, new_call):
            return None

        return InterruptReason.LOOP


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


# ---------------------------------------------------------------------------
# Token / cost helpers
#
# So callers don't have to compute cost_usd by hand. Pass a model name and the
# token counts and get a USD figure you can put on ToolCall.cost_usd, which the
# BudgetDetector already understands.
#
# Prices are USD per 1,000,000 tokens (input, output). Update these as provider
# pricing changes -- they are intentionally easy to edit. Unknown models fall
# back to DEFAULT_PRICING so a typo never silently costs $0.
# ---------------------------------------------------------------------------

# (input_per_million, output_per_million)
PRICING: Dict[str, tuple] = {
    "gpt-4o":            (2.50, 10.00),
    "gpt-4o-mini":      (0.15,  0.60),
    "gpt-4.1":          (2.00,  8.00),
    "gpt-4.1-mini":     (0.40,  1.60),
    "claude-opus-4":    (15.00, 75.00),
    "claude-sonnet-4":  (3.00, 15.00),
    "claude-haiku-4":   (0.80,  4.00),
}

DEFAULT_PRICING: tuple = (5.00, 15.00)


def cost_from_tokens(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate the USD cost of one model call from its token usage.

    Example:
        usage = response.usage  # from your LLM provider
        call.cost_usd = cost_from_tokens("gpt-4o", usage.input_tokens, usage.output_tokens)

    Unknown model names use DEFAULT_PRICING rather than returning 0, so a
    misspelled model name can never make a call look free to the BudgetDetector.
    """
    in_price, out_price = PRICING.get(model, DEFAULT_PRICING)
    return (input_tokens / 1_000_000) * in_price + (output_tokens / 1_000_000) * out_price
