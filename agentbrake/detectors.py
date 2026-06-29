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
    """Flags when the same tool is called too many times in a recent window.

    Unlike LoopDetector, this does NOT require the arguments to match, and does
    NOT require the calls to be consecutive. It catches two common failure modes
    that exact-hash loop detection misses:

      * retry storms   -> search("A"), search("B"), search("C"), ...
      * alternating loops -> search, read, search, read, search, ...

    It counts how many times `new_call.name` appears among the last `window`
    calls (including the new one). If that count reaches `max_calls_per_tool`,
    the run is flagged as a loop.

    Args:
        max_calls_per_tool: how many calls to the same tool are allowed inside
            the window before the brake trips. Must be >= 2.
        window: how many recent calls to look back over. Must be
            >= max_calls_per_tool. A larger window catches slower loops;
            a smaller one only catches tight bursts.
    """

    def __init__(self, max_calls_per_tool: int = 5, window: int = 10):
        if max_calls_per_tool < 2:
            raise ValueError("max_calls_per_tool must be >= 2")
        if window < max_calls_per_tool:
            raise ValueError("window must be >= max_calls_per_tool")
        self.max_calls_per_tool = max_calls_per_tool
        self.window = window

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        recent = run_state.calls[-(self.window - 1):]
        # +1 for the new call we are about to make
        same_tool = sum(1 for c in recent if c.name == new_call.name) + 1
        if same_tool >= self.max_calls_per_tool:
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


# ---------------------------------------------------------------------------
# Token / cost helpers
#
# So callers don't have to compute cost_usd by hand. Pass a model name and the
# token counts and get a USD figure you can put on ToolCall.cost_usd, which the
# BudgetDetector already understands.
#
# Prices are USD per 1,000,000 tokens (input, output). Update these as provider
# pricing changes — they are intentionally easy to edit. Unknown models fall
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
