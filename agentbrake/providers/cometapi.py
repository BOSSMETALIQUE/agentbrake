"""CometAPI provider: automatic token-based cost tracking for LLM calls.

CometAPI (https://www.cometapi.com) is an OpenAI-compatible gateway exposing
500+ models behind a single endpoint. Its responses carry the standard
``usage`` token counts, so AgentBrake can price every call through the
existing ``cost_from_tokens`` helper instead of a per-call flat fee.

Three entry points, no hidden control flow:

* ``track(response, model)`` — you make the API call yourself with whatever
  client you like; this only extracts token usage and prices it.
* ``record(call)`` — push a priced call into the active AgentBrake run so the
  ``BudgetDetector`` sees real LLM spend. No active run, no effect.
* ``complete(model, messages, ...)`` — a thin convenience wrapper around the
  ``openai`` client pointed at CometAPI: call, ``track``, ``record`` — pass
  ``record=False`` to keep the result out of the run.

The AgentBrake core never imports this module; the integration is opt-in by
construction. Wire-up is one line each way::

    agentbrake.init(budget_usd=5.0)
    result = cometapi.complete("gpt-4o", messages)  # cost tracked, budget enforced

Honest limits: the USD figure is an *estimate* from AgentBrake's ``PRICING``
table (unknown models fall back to ``DEFAULT_PRICING``); what CometAPI
actually bills you can differ. A response with no ``usage`` block is tracked
at $0.00 rather than guessed.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .. import current_run
from ..detectors import cost_from_tokens
from ..types import AgentBrakeInterrupt, ToolCall

__all__ = [
    "CometAPICall",
    "complete",
    "record",
    "track",
    "DEFAULT_BASE_URL",
    "API_KEY_ENV_VAR",
]

DEFAULT_BASE_URL = "https://api.cometapi.com/v1"
API_KEY_ENV_VAR = "COMETAPI_KEY"


class CometAPICall(BaseModel):
    """One priced LLM call: the raw response plus its usage and USD estimate."""

    model: str
    prompt_tokens: Optional[int] = None  # None when the response had no usage
    completion_tokens: Optional[int] = None
    cost_usd: float = 0.0
    response: Any = None  # the untouched provider response


def _field(obj: Any, name: str) -> Any:
    """Read ``name`` from an attribute-style or dict-style object."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def track(response: Any, model: str) -> CometAPICall:
    """Extract token usage from an OpenAI-compatible response and price it.

    Works with ``openai`` SDK response objects and plain dicts alike. When the
    response carries no usage at all, the call is priced at $0.00 with token
    counts left as ``None`` — AgentBrake will not invent token counts, so a
    provider that omits usage yields an under-estimate, never a crash.
    """
    usage = _field(response, "usage")
    prompt_tokens = _field(usage, "prompt_tokens")
    completion_tokens = _field(usage, "completion_tokens")

    if prompt_tokens is None and completion_tokens is None:
        return CometAPICall(model=model, response=response)

    prompt = int(prompt_tokens or 0)
    completion = int(completion_tokens or 0)
    return CometAPICall(
        model=model,
        prompt_tokens=prompt,
        completion_tokens=completion,
        cost_usd=cost_from_tokens(model, prompt, completion),
        response=response,
    )


def record(call: CometAPICall) -> None:
    """Record a priced LLM call into the active AgentBrake run, if any.

    Appends a ``ToolCall`` named ``llm:cometapi:<model>`` carrying the real
    ``cost_usd`` to the run's state (so it shows up in the call history like
    any other call), then applies the run's own ``BudgetDetector`` with the
    same projected-cost semantics as ``guard()``.

    Unlike guarded tool calls, an LLM call's cost is only known *after* the
    tokens are spent — so the spend is always recorded, and the interrupt (if
    the ceiling is crossed) fires right after the offending call instead of
    before it. Overshoot is bounded by one call. The interrupt is raised
    locally regardless of the run's mode.

    With no active run this is a no-op, so tracking works without enforcement.
    """
    active = current_run()
    if active is None:
        return

    tool_call = ToolCall(
        name=f"llm:cometapi:{call.model}",
        args={
            "model": call.model,
            "prompt_tokens": call.prompt_tokens,
            "completion_tokens": call.completion_tokens,
        },
        cost_usd=call.cost_usd,
        outcome="ok",  # the API call already succeeded by the time we price it
    )
    # Projected check against the pre-call state, exactly like guard()...
    reason = active.budget_detector.check(active.state, tool_call)
    # ...but the spend is recorded either way: the tokens are already bought.
    active.state.append(tool_call)
    if reason is not None:
        active.state.status = "interrupted"
        raise AgentBrakeInterrupt(
            reason,
            context={
                "run_id": active.state.run_id,
                "tool": tool_call.name,
                "model": call.model,
                "cost_usd": call.cost_usd,
                "total_cost_usd": active.state.total_cost_usd,
            },
        )


# complete() takes a `record=` keyword that shadows the function name in its
# own scope; this alias keeps the function reachable from there.
_record = record


def _build_client(api_key: Optional[str], base_url: str) -> Any:
    """Instantiate an ``openai`` client pointed at CometAPI.

    The import is deliberately lazy: the AgentBrake core must stay usable
    without the ``openai`` package installed.
    """
    try:
        from openai import OpenAI
    except ImportError as e:
        raise ImportError(
            "the CometAPI provider needs the 'openai' package — install it "
            "with: pip install py-agentbrake[cometapi]"
        ) from e

    key = api_key or os.environ.get(API_KEY_ENV_VAR)
    if not key:
        raise RuntimeError(
            f"no CometAPI key — pass api_key=... or set the {API_KEY_ENV_VAR} "
            "environment variable (sign up at https://www.cometapi.com)"
        )
    return OpenAI(api_key=key, base_url=base_url)


def complete(
    model: str,
    messages: List[Dict[str, Any]],
    *,
    api_key: Optional[str] = None,
    base_url: str = DEFAULT_BASE_URL,
    client: Optional[Any] = None,
    record: bool = True,
    **kwargs: Any,
) -> CometAPICall:
    """Make one chat-completion call through CometAPI and price it.

    By default the priced call is also recorded into the active AgentBrake
    run (see ``record()``), so a run's ``BudgetDetector`` sees real LLM spend
    and can interrupt on overrun; pass ``record=False`` for tracking only.

    Pass ``client=`` to reuse an existing OpenAI-compatible client (the
    ``base_url``/``api_key`` arguments are then ignored); otherwise a client
    is built from ``api_key`` or the ``COMETAPI_KEY`` environment variable.
    Extra ``kwargs`` go straight to ``chat.completions.create``.
    """
    if client is None:
        client = _build_client(api_key, base_url)
    response = client.chat.completions.create(model=model, messages=messages, **kwargs)
    result = track(response, model)
    if record:
        _record(result)
    return result
