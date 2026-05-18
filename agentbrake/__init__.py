"""AgentBrake: circuit breaker SDK for LLM agents."""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

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
    )


def _require_config() -> _Config:
    if _config is None:
        raise RuntimeError("agentbrake.init() must be called before @guard()")
    return _config


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
                if reason is not None:
                    cfg.run_state.status = "interrupted"
                    raise AgentBrakeInterrupt(
                        reason,
                        context={
                            "run_id": cfg.run_state.run_id,
                            "tool": name,
                            "total_cost_usd": cfg.run_state.total_cost_usd,
                        },
                    )

            result = fn(name, args or {}, *extra, **kwargs)
            cfg.run_state.append(call)

            if cfg.mode == "remote":
                # TODO: ship run_state delta to backend via client.py
                pass

            return result

        return wrapper

    return decorator
