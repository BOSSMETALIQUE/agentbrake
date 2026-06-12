"""AgentBrake: circuit breaker SDK for LLM agents."""

from __future__ import annotations

import functools
import sys
from contextvars import ContextVar, Token
from typing import Any, Callable, List, Optional

from .client import AgentBrakeClient
from .detectors import BudgetDetector, EscalationDetector, LoopDetector
from .types import AgentBrakeInterrupt, InterruptReason, RunState, ToolCall

__version__ = "0.0.2"

__all__ = [
    "init",
    "run",
    "guard",
    "current_run",
    "Run",
    "AgentBrakeInterrupt",
    "InterruptReason",
    "RunState",
    "ToolCall",
    "__version__",
]

_FIXED_COST_PER_CALL_USD = 0.01
_REMOTE_WAIT_TIMEOUT_S = 300.0


class Run:
    """One guarded agent run: configuration, detectors, and a fresh RunState.

    Use as a context manager for per-run isolation:

        with agentbrake.run(budget_usd=5.0) as r:
            agent.invoke(...)
        print(r.state.total_cost_usd)

    Each Run owns its own RunState, so one run exhausting its budget (or
    tripping the loop detector) can never poison the next. The active run is
    tracked with a ContextVar, so concurrent runs in separate threads or
    asyncio tasks stay isolated. A Run is single-use: open a new one per
    agent task instead of re-entering an old one.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        allowed_tools: Optional[List[str]] = None,
        budget_usd: float = 0.0,
        api_url: str = "http://localhost:8000",
        mode: str = "local",
    ):
        if mode not in {"local", "remote"}:
            raise ValueError("mode must be 'local' or 'remote'")
        self.api_key = api_key
        self.allowed_tools = list(allowed_tools or [])
        self.budget_usd = budget_usd
        self.api_url = api_url
        self.mode = mode
        self.loop_detector = LoopDetector()
        self.budget_detector = BudgetDetector(budget_usd)
        self.escalation_detector = EscalationDetector(self.allowed_tools)
        self.state = RunState()
        self.client = AgentBrakeClient(api_url) if mode == "remote" else None
        self._token: Optional[Token] = None

    def __enter__(self) -> "Run":
        self._token = _current_run.set(self)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if self._token is not None:
            _current_run.reset(self._token)
            self._token = None
        if self.client is not None:
            self.client.close()
        if self.state.status == "running":
            self.state.status = "completed" if exc_type is None else "failed"
        return False


_current_run: ContextVar[Optional[Run]] = ContextVar(
    "agentbrake_current_run", default=None
)
_default_run: Optional[Run] = None


def init(
    api_key: Optional[str] = None,
    allowed_tools: Optional[List[str]] = None,
    budget_usd: float = 0.0,
    api_url: str = "http://localhost:8000",
    mode: str = "local",
) -> None:
    """Configure the process-wide default run. Resets all state on each call.

    Guarded calls made outside a `with agentbrake.run(...)` block share this
    default run. For per-task isolation, prefer run().
    """
    global _default_run
    _default_run = Run(
        api_key=api_key,
        allowed_tools=allowed_tools,
        budget_usd=budget_usd,
        api_url=api_url,
        mode=mode,
    )


def run(
    api_key: Optional[str] = None,
    allowed_tools: Optional[List[str]] = None,
    budget_usd: Optional[float] = None,
    api_url: Optional[str] = None,
    mode: Optional[str] = None,
) -> Run:
    """Create an isolated Run; use it as a context manager.

    Arguments left as None inherit from the most recent init() call, so you
    can init() once with the allowlist and open a cheap fresh run per task:

        agentbrake.init(allowed_tools=["search"])
        with agentbrake.run(budget_usd=5.0) as r:
            ...
    """
    base = _default_run
    return Run(
        api_key=api_key if api_key is not None else (base.api_key if base else None),
        allowed_tools=(
            allowed_tools
            if allowed_tools is not None
            else (base.allowed_tools if base else None)
        ),
        budget_usd=(
            budget_usd if budget_usd is not None else (base.budget_usd if base else 0.0)
        ),
        api_url=(
            api_url
            if api_url is not None
            else (base.api_url if base else "http://localhost:8000")
        ),
        mode=mode if mode is not None else (base.mode if base else "local"),
    )


def current_run() -> Optional[Run]:
    """The active run: the innermost `with agentbrake.run(...)` block if any,
    else the process-wide default created by init(), else None."""
    return _current_run.get() or _default_run


def _require_run() -> Run:
    active = current_run()
    if active is None:
        raise RuntimeError(
            "no active run — call agentbrake.init() or wrap the agent in "
            "'with agentbrake.run(...)' before using @guard()"
        )
    return active


def _build_context(active: Run, name: str) -> dict:
    """Per-interrupt context (sent to backend, attached to exception)."""
    return {
        "run_id": active.state.run_id,
        "tool": name,
        "total_cost_usd": active.state.total_cost_usd,
        "run_state": active.state.model_dump(mode="json"),
    }


def _handle_remote_interrupt(
    active: Run,
    reason: InterruptReason,
    context: dict,
) -> bool:
    """Submit interrupt, wait for human decision. Returns True if approved.

    Falls back to local-mode behavior (raise) if the backend is unreachable —
    the SDK must fail safely: if validation can't happen, default to stop.
    """
    assert active.client is not None
    try:
        interrupt_id, url = active.client.submit_interrupt(
            run_id=active.state.run_id,
            reason=reason.value.upper(),
            context=context,
        )
    except Exception as e:  # noqa: BLE001 — backend unreachable, fail closed
        print(
            f"🛑 AgentBrake [{reason.value.upper()}] detected, but backend at "
            f"{active.api_url} is unreachable ({e}). Stopping run.",
            file=sys.stderr,
        )
        return False

    print(
        f"🛑 {reason.value.upper()} detected. Validate or kill: {url}",
        file=sys.stderr,
    )

    try:
        decision = active.client.wait_for_decision(
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
            active = _require_run()

            call = ToolCall(name=name, args=args or {}, cost_usd=_FIXED_COST_PER_CALL_USD)

            for detector in (
                active.escalation_detector,
                active.loop_detector,
                active.budget_detector,
            ):
                reason = detector.check(active.state, call)
                if reason is None:
                    continue

                context = _build_context(active, name)

                if active.mode == "remote" and _handle_remote_interrupt(
                    active, reason, context
                ):
                    # Human said go: execute as if the detector hadn't fired.
                    # Skip remaining detectors.
                    break

                active.state.status = "interrupted"
                raise AgentBrakeInterrupt(reason, context=context)

            # Record the attempt BEFORE executing so a failing tool still
            # counts toward loop detection and budget — otherwise an agent
            # retrying the same failing call forever would be invisible.
            active.state.append(call)
            try:
                result = fn(name, args or {}, *extra, **kwargs)
            except BaseException as e:
                call.outcome = "error"
                call.error = repr(e)
                raise
            call.outcome = "ok"
            return result

        return wrapper

    return decorator
