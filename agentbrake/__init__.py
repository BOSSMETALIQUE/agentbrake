"""AgentBrake: circuit breaker SDK for LLM agents."""

from __future__ import annotations

import functools
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from .client import AgentBrakeClient
from .detectors import BudgetDetector, EscalationDetector, LoopDetector
from .types import AgentBrakeInterrupt, InterruptReason, RunState, ToolCall

__all__ = [
    "init",
    "guard",
    "AgentBrakeInterrupt",
    "InterruptReason",
    "RunState",
    "ToolCall",
]

_FIXED_COST_PER_CALL_USD = 0.01
_REMOTE_WAIT_TIMEOUT_S = 300.0


@dataclass
class _Config:
    api_key: Optional[str] = None
    allowed_tools: List[str] = field(default_factory=list)
    budget_usd: float = 0.0
    api_url: str = "http://localhost:8000"
    mode: str = "local"
    loop_detector: Optional[LoopDetector] = None
    budget_detector: Optional[BudgetDetector] = None
    escalation_detector: Optional[EscalationDetector] = None
    run_state: Optional[RunState] = None
    client: Optional[AgentBrakeClient] = None


_config: Optional[_Config] = None


def init(
    api_key: Optional[str] = None,
    allowed_tools: Optional[List[str]] = None,
    budget_usd: float = 0.0,
    api_url: str = "http://localhost:8000",
    mode: str = "local",
) -> None:
    """Configure the SDK. Must be called before using @guard()."""
    if mode not in {"local", "remote"}:
        raise ValueError("mode must be 'local' or 'remote'")

    global _config
    _config = _Config(
        api_key=api_key,
        allowed_tools=list(allowed_tools or []),
        budget_usd=budget_usd,
        api_url=api_url,
        mode=mode,
        loop_detector=LoopDetector(),
        budget_detector=BudgetDetector(budget_usd),
        escalation_detector=EscalationDetector(allowed_tools or []),
        run_state=RunState(),
        client=AgentBrakeClient(api_url) if mode == "remote" else None,
    )


def _require_config() -> _Config:
    if _config is None:
        raise RuntimeError("agentbrake.init() must be called before @guard()")
    return _config


def _build_context(cfg: _Config, name: str) -> dict:
    """Per-interrupt context (sent to backend, attached to exception)."""
    assert cfg.run_state is not None
    return {
        "run_id": cfg.run_state.run_id,
        "tool": name,
        "total_cost_usd": cfg.run_state.total_cost_usd,
        "run_state": cfg.run_state.model_dump(mode="json"),
    }


def _handle_remote_interrupt(
    cfg: _Config,
    reason: InterruptReason,
    context: dict,
) -> bool:
    """Submit interrupt, wait for human decision. Returns True if approved.

    Falls back to local-mode behavior (raise) if the backend is unreachable —
    the SDK must fail safely: if validation can't happen, default to stop.
    """
    assert cfg.client is not None
    assert cfg.run_state is not None
    try:
        interrupt_id, url = cfg.client.submit_interrupt(
            run_id=cfg.run_state.run_id,
            reason=reason.value.upper(),
            context=context,
        )
    except Exception as e:  # noqa: BLE001 — backend unreachable, fail closed
        print(
            f"🛑 AgentBrake [{reason.value.upper()}] detected, but backend at "
            f"{cfg.api_url} is unreachable ({e}). Stopping run.",
            file=sys.stderr,
        )
        return False

    print(
        f"🛑 {reason.value.upper()} detected. Validate or kill: {url}",
        file=sys.stderr,
    )

    try:
        decision = cfg.client.wait_for_decision(
            interrupt_id, timeout=_REMOTE_WAIT_TIMEOUT_S
        )
    except TimeoutError:
        raise AgentBrakeInterrupt(
            InterruptReason.TIMEOUT,
            context={**context, "interrupt_id": interrupt_id},
        )

    if decision == "approved":
        print(
            f"✓ AgentBrake [{reason.value.upper()}] resumed by human ({url})",
            file=sys.stderr,
        )
        return True
    return False


def guard() -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps a tool-dispatch function with the circuit breaker."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(name: str, args: Optional[dict] = None, *extra: Any, **kwargs: Any) -> Any:
            cfg = _require_config()
            assert cfg.run_state is not None
            assert cfg.loop_detector and cfg.budget_detector and cfg.escalation_detector

            call = ToolCall(name=name, args=args or {}, cost_usd=_FIXED_COST_PER_CALL_USD)

            for detector in (cfg.escalation_detector, cfg.loop_detector, cfg.budget_detector):
                reason = detector.check(cfg.run_state, call)
                if reason is None:
                    continue

                context = _build_context(cfg, name)

                if cfg.mode == "remote":
                    approved = _handle_remote_interrupt(cfg, reason, context)
                    if approved:
                        # Human said go: execute and record as if the
                        # detector hadn't fired. Skip remaining detectors.
                        result = fn(name, args or {}, *extra, **kwargs)
                        cfg.run_state.append(call)
                        return result
                    cfg.run_state.status = "interrupted"
                    raise AgentBrakeInterrupt(reason, context=context)

                # local mode: original behavior
                cfg.run_state.status = "interrupted"
                raise AgentBrakeInterrupt(reason, context=context)

            result = fn(name, args or {}, *extra, **kwargs)
            cfg.run_state.append(call)
            return result

        return wrapper

    return decorator
