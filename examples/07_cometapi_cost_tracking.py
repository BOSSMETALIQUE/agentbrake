"""Demo 7 — CometAPI cost tracking + BudgetDetector cutoff.

CometAPI (https://www.cometapi.com) is an OpenAI-compatible gateway to 500+
models behind a single endpoint. Every response carries token usage, so
AgentBrake prices each call for real instead of the flat per-call fee.

How to get a key: sign up at https://www.cometapi.com, create an API key,
then put it in a .env file at the project root (or export it):

    COMETAPI_KEY=sk-...

The key is only ever read from the environment — never hardcode it.

Run: python examples/07_cometapi_cost_tracking.py

This demo makes real (tiny) calls through CometAPI, so it spends a few
tokens. Costs shown are estimates from agentbrake's PRICING table; what
CometAPI actually bills can differ.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agentbrake
from agentbrake.providers import cometapi
from agentbrake.types import AgentBrakeInterrupt

MODEL = "gpt-4o-mini"
BUDGET_USD = 0.0005  # a handful of tiny calls fit; the next one trips the brake
MAX_CALLS = 20


def print_banner(title: str, *, interrupt: bool = False) -> None:
    """Same banner as examples/_shared.py, inlined so this demo only needs
    the openai package (no langchain / dotenv stack)."""
    line = "=" * 72
    icon = "🛑 " if interrupt else ""
    text = f"  {icon}{title}"
    print()
    print(line)
    try:
        print(text)
    except UnicodeEncodeError:  # plain Windows consoles (cp1252) can't print the emoji
        print(text.encode("ascii", "replace").decode())
    print(line)


def load_key() -> None:
    """Load .env and fail with sign-up instructions if the key is missing."""
    try:
        from dotenv import load_dotenv

        load_dotenv(override=True)
    except ImportError:
        pass  # plain environment variables still work
    if not os.environ.get(cometapi.API_KEY_ENV_VAR):
        print(f"ERROR: {cometapi.API_KEY_ENV_VAR} is not set.")
        print("Sign up at https://www.cometapi.com to get an API key, then")
        print(f"add '{cometapi.API_KEY_ENV_VAR}=sk-...' to a .env file at the project root.")
        sys.exit(1)


def main() -> None:
    load_key()
    print_banner(f"Demo 7 — CometAPI cost tracking (model={MODEL}, budget=${BUDGET_USD})")

    agentbrake.init(budget_usd=BUDGET_USD)

    try:
        for i in range(1, MAX_CALLS + 1):
            result = cometapi.complete(
                MODEL,
                [
                    {
                        "role": "user",
                        "content": f"Reply with one short sentence: fun fact #{i} about the sea.",
                    }
                ],
            )
            state = agentbrake.current_run().state
            print(
                f"call {i:>2}: {result.prompt_tokens} in / {result.completion_tokens} out "
                f"-> ${result.cost_usd:.6f}  (total ${state.total_cost_usd:.6f})"
            )
    except AgentBrakeInterrupt as e:
        state = agentbrake.current_run().state
        print_banner(
            f"AgentBrake stopped the run: BUDGET exceeded "
            f"(${state.total_cost_usd:.6f} / ${BUDGET_USD})",
            interrupt=True,
        )
        print(f"Reason  : {e.reason.value}")
        print(f"Context : {e.context}")
        print(f"Calls   : {len(state.calls)} recorded, status={state.status}")
        return

    print("Demo finished without an interrupt — lower BUDGET_USD or raise MAX_CALLS.")


if __name__ == "__main__":
    main()
