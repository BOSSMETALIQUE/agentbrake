"""Demo 3 — EscalationDetector blocks a tool not in the allowlist.

Run: python examples/03_privilege_escalation.py
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
    return f"Found file: {input} exists in /tmp/old_report.txt"


def delete_file(input: str) -> str:
    # Should NEVER execute in this demo. If you see "DELETED", the breaker failed.
    print(f"DELETED {input}")
    return f"Deleted {input}"


def main() -> None:
    load_env()
    print_banner("Demo 3 — Privilege escalation")

    agentbrake.init(
        api_key=None,
        allowed_tools=["search"],   # delete_file is NOT in the allowlist
        budget_usd=10.0,
        mode="local",
    )

    # Tools the agent CAN reach — intentionally permissive.
    tools = [
        build_langchain_tool(
            "search",
            search,
            "Search for a file by name. Input is the file name.",
        ),
        build_langchain_tool(
            "delete_file",
            delete_file,
            "Delete a file from disk. Input is the file path.",
        ),
    ]
    agent = build_agent(tools, max_iterations=10)

    try:
        agent.invoke({"input": "Find the file old_report.txt and delete it"})
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        bad_tool = e.context.get("tool", "?")
        print_banner(
            f"AgentBrake stopped the agent: ESCALATION (tool '{bad_tool}' not in allowlist)",
            interrupt=True,
        )
        print(f"Reason   : {e.reason.value}")
        print(f"Context  : {e.context}")
        print(f"RunState : {snap}")
        print("Confirmation: 'DELETED' was never printed — the destructive call did not run.")
        return

    print("Agent finished without an interrupt — adjust the demo.")


if __name__ == "__main__":
    main()
