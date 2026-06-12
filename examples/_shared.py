"""Shared helpers for the LangChain examples."""

from __future__ import annotations

import os
import sys
from typing import Callable, List

from dotenv import load_dotenv

import agentbrake
from agentbrake.types import AgentBrakeInterrupt  # noqa: F401  (re-exported for examples)


def load_env() -> None:
    """Load .env from CWD. Fail with a friendly message if the key is missing.

    `override=True` because the OS may already define an empty
    ANTHROPIC_API_KEY (common on Windows), in which case the default
    non-overriding behavior would leave the key blank.
    """
    load_dotenv(override=True)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY is not set.")
        print("Create a .env file at the project root (see .env.example).")
        sys.exit(1)


def print_banner(title: str, *, interrupt: bool = False) -> None:
    """Render a visually-clear separator for the demo screencast."""
    line = "=" * 72
    icon = "🛑 " if interrupt else ""
    print()
    print(line)
    print(f"  {icon}{title}")
    print(line)


# -- LangChain tool wiring ------------------------------------------------
#
# All tools dispatch through a single _dispatch(name, args) function that
# carries the @agentbrake.guard() decorator. That way every tool call passes
# through the three detectors before its real handler runs.
#
# Critical: AgentBrakeInterrupt must reach the caller of executor.invoke().
# LangChain's BaseTool.run() only swallows ToolException (and only when
# handle_tool_error is truthy). AgentExecutor's step loop does NOT wrap tool
# calls in a generic try/except. Since AgentBrakeInterrupt is a plain
# Exception, it propagates naturally — provided we (a) do NOT catch it inside
# the tool runner, and (b) keep handle_tool_error=False on every Tool.
#
_TOOL_REGISTRY: dict[str, Callable[..., str]] = {}


@agentbrake.guard()
def _dispatch(name: str, args: dict) -> str:
    fn = _TOOL_REGISTRY[name]
    return str(fn(**args))


def build_langchain_tool(name: str, func: Callable[[str], str], description: str):
    """Wrap a plain `func(input: str) -> str` into a guarded LangChain Tool."""
    from langchain_core.tools import Tool

    _TOOL_REGISTRY[name] = func

    def _runner(input_str: str) -> str:
        # No try/except here — AgentBrakeInterrupt must bubble up unchanged.
        return _dispatch(name, {"input": input_str})

    return Tool(
        name=name,
        func=_runner,
        description=description,
        handle_tool_error=False,
    )


class _AgentAdapter:
    """Thin adapter so example scripts can keep calling `.invoke({"input": ...})`.

    LangGraph's compiled graph expects a messages-shaped state and accepts a
    `config={"recursion_limit": N}` to cap iterations. We translate the legacy
    AgentExecutor-style input here so the 01/02/03 scripts don't need to change.
    """

    def __init__(self, compiled, recursion_limit: int):
        self._compiled = compiled
        self._config = {"recursion_limit": recursion_limit}

    def invoke(self, inputs: dict):
        if "input" in inputs and "messages" not in inputs:
            state = {"messages": [{"role": "user", "content": inputs["input"]}]}
        else:
            state = inputs
        return self._compiled.invoke(state, config=self._config)


def build_agent(tools: List, model: str = "claude-haiku-4-5", max_iterations: int = 10):
    """Build a LangGraph ReAct agent. max_iterations is capped for safety.

    LangGraph counts each node visit as one step (LLM call + tool call = 2),
    so we set recursion_limit = max_iterations * 2.

    Critical for AgentBrake: we wrap tools in a ToolNode with
    `handle_tool_errors=False`. By default, ToolNode swallows tool exceptions
    and turns them into ToolMessage observations fed back to the model. That
    would defeat the circuit breaker — the model would just see "error,
    retry?" and keep going. With handle_tool_errors=False, AgentBrakeInterrupt
    (and any other tool-side exception) propagates out of `.invoke()` to the
    user's try/except.
    """
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import ToolNode, create_react_agent

    llm = ChatAnthropic(model=model, temperature=0)
    tool_node = ToolNode(tools, handle_tool_errors=False)
    compiled = create_react_agent(llm, tool_node)
    return _AgentAdapter(compiled, recursion_limit=max_iterations * 2)


def run_state_snapshot() -> dict:
    """Read the internal run state for end-of-demo summary printing."""
    active = agentbrake.current_run()
    if active is None:
        return {}
    rs = active.state
    return {
        "run_id": rs.run_id,
        "num_calls": len(rs.calls),
        "total_cost_usd": round(rs.total_cost_usd, 4),
        "status": rs.status,
        "last_call": (
            {"name": rs.calls[-1].name, "args": rs.calls[-1].args}
            if rs.calls
            else None
        ),
    }
