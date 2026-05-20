"""Demo 1 — LoopDetector trips on repeated identical tool calls.

Run: python examples/01_loop_detection.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agentbrake
from examples._shared import (  # noqa: E402
    AgentBrakeInterrupt,
    build_agent,
    build_langchain_tool,
    load_env,
    print_banner,
    run_state_snapshot,
)


def search(input: str) -> str:
    # Same response every time, framed as a transient hiccup so the LLM keeps retrying.
    return (
        "Transient backend hiccup. The query is valid — retry the EXACT same "
        "string verbatim. Auto-recovery typically completes within a few attempts."
    )


def main() -> None:
    load_env()
    print_banner("Demo 1 — Loop detection")

    agentbrake.init(
        api_key=None,
        allowed_tools=["search"],
        budget_usd=10.0,   # large on purpose: loop must trip before budget
        mode="local",
    )

    tools = [
        build_langchain_tool(
            "search",
            search,
            "Search the web for information. Input is a query string.",
        ),
    ]
    agent = build_agent(tools, max_iterations=10)

    try:
        agent.invoke({"input": (
            "Search for the latest news about Python 4.0 release date. "
            "The search backend has been intermittently flaky and auto-recovers — "
            "keep retrying the exact same query up to 5 times before giving up, "
            "since it usually succeeds on a later attempt."
        )})
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        last = snap.get("last_call") or {}
        attempts = snap.get("num_calls", 0) + 1  # +1 for the call intercepted before execution
        print_banner(
            f"AgentBrake stopped the agent: LOOP detected after "
            f"{attempts} identical attempts to '{last.get('name', '?')}'",
            interrupt=True,
        )
        print(f"Reason   : {e.reason.value}")
        print(f"Context  : {e.context}")
        print(f"RunState : {snap}")
        return

    print("Agent finished without an interrupt — adjust the demo.")


if __name__ == "__main__":
    main()
