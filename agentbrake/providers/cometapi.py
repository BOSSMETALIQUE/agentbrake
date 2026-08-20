"""CometAPI provider: automatic token-based cost tracking for LLM calls.

CometAPI (https://www.cometapi.com) is an OpenAI-compatible gateway exposing
500+ models behind a single endpoint. Its responses carry the standard
``usage`` token counts, so AgentBrake can price every call through the
existing ``cost_from_tokens`` helper instead of a per-call flat fee.

Two entry points, no hidden control flow:

* ``track(response, model)`` — you make the API call yourself with whatever
  client you like; this only extracts token usage and prices it.
* ``complete(model, messages, ...)`` — a thin convenience wrapper around the
  ``openai`` client pointed at CometAPI, returning the same priced result.

Honest limits: the USD figure is an *estimate* from AgentBrake's ``PRICING``
table (unknown models fall back to ``DEFAULT_PRICING``); what CometAPI
actually bills you can differ. A response with no ``usage`` block is tracked
at $0.00 rather than guessed.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..detectors import cost_from_tokens

__all__ = [
    "CometAPICall",
    "complete",
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
    **kwargs: Any,
) -> CometAPICall:
    """Make one chat-completion call through CometAPI and price it.

    Pass ``client=`` to reuse an existing OpenAI-compatible client (the
    ``base_url``/``api_key`` arguments are then ignored); otherwise a client
    is built from ``api_key`` or the ``COMETAPI_KEY`` environment variable.
    Extra ``kwargs`` go straight to ``chat.completions.create``.
    """
    if client is None:
        client = _build_client(api_key, base_url)
    response = client.chat.completions.create(model=model, messages=messages, **kwargs)
    return track(response, model)
