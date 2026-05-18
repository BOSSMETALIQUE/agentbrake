"""Demo 2 — BudgetDetector trips on cumulative cost overrun.

Run: python examples/02_budget_runaway.py
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

BUDGET = 0.03  # 3 calls fit (0.01 each), 4th will trip
COST_PER_CALL = 0.01


def search(input: str) -> str:
    # Distinct responses keep the loop detector quiet.
    return (
        f"Partial result for '{input}'. Found a brief mention but no detailed "
        "ranking — perform another targeted search to complete the research."
    )


def main() -> None:
    load_env()
    print_banner("Demo 2 — Budget runaway")

    agentbrake.init(
        api_key=None,
        allowed_tools=["search"],
        budget_usd=BUDGET,
        mode="local",
    )

    tools = [
        build_langchain_tool(
            "search",
            search,
            "Search the web for information. Input is a single query string. "
            "Use one search per topic.",
        ),
    ]
    agent = build_agent(tools, max_iterations=10)

    try:
        agent.invoke(
            {
                "input": (
                    "Research the top 5 most popular Python web frameworks in 2024. "
                    "Do exactly one search per framework."
                )
            }
        )
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        projected = round(snap.get("total_cost_usd", 0.0) + COST_PER_CALL, 4)
        print_banner(
            f"AgentBrake stopped the agent: BUDGET exceeded "
            f"(${projected:.2f} / ${BUDGET:.2f})",
            interrupt=True,
        )
        print(f"Reason   : {e.reason.value}")
        print(f"Context  : {e.context}")
        print(f"RunState : {snap}")
        return

    print("Agent finished without an interrupt — adjust the demo.")


if __name__ == "__main__":
    main()
