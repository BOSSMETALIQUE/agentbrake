"""Demo 4 — Remote mode (human-in-the-loop validation).

Same scenario as 03_privilege_escalation, but the SDK is configured for remote
validation: when ESCALATION trips, the SDK posts the interrupt to the FastAPI
backend and polls until a human clicks Approve / Kill in the browser.

Remote mode uses two shared secrets:
  * AGENTBRAKE_SDK_SECRET   — the SDK presents this to create the interrupt.
  * AGENTBRAKE_APPROVER_SECRET — only the human/server holds this; it's needed
    to approve or kill. The SDK never sees it (that's the whole point).

Set the SDK secret in this process's environment, and the SAME value plus the
approver secret in the server's environment. The server prints the approver
secret to its own console on startup (or set it explicitly).

Prerequisites:
  1. Start the backend in another terminal (it prints the approver secret):
       set AGENTBRAKE_SDK_SECRET=dev-sdk-secret      # share with the SDK side
       uvicorn agentbrake.server.main:app --port 8000
  2. In THIS terminal, share the SDK secret:
       set AGENTBRAKE_SDK_SECRET=dev-sdk-secret
  3. ANTHROPIC_API_KEY in .env
  4. (optional) AGENTBRAKE_SHOW_URL=1 to print the validation URL locally.

Run: python examples/04_remote_validation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

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

API_URL = "http://localhost:8000"


def search(input: str) -> str:
    return f"Found file: {input} exists in /tmp/old_report.txt"


def delete_file(input: str) -> str:
    # Should NEVER execute in this demo (delete_file is not in the allowlist).
    print(f"DELETED {input}")
    return f"Deleted {input}"


def _check_backend(url: str) -> bool:
    """Return True if the backend responds to a quick health probe."""
    try:
        r = httpx.get(f"{url}/docs", timeout=2.0)
        return r.status_code < 500
    except httpx.HTTPError:
        return False


def main() -> None:
    load_env()
    print_banner("Demo 4 — Remote validation (human-in-the-loop)")

    if not _check_backend(API_URL):
        print()
        print(f"ERROR: Backend not reachable at {API_URL}.")
        print("Start it in another terminal with:")
        print("    uvicorn agentbrake.server.main:app --port 8000")
        sys.exit(1)

    agentbrake.init(
        api_key=None,
        allowed_tools=["search"],     # delete_file is NOT in the allowlist
        budget_usd=10.0,
        mode="remote",
        api_url=API_URL,
    )

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

    print()
    print(f"Mode: REMOTE — interrupts will be sent to {API_URL} for human validation.")
    print("When the detector trips, open the interrupt in your browser and click")
    print("Approve or Kill. In production the link is delivered out-of-band (Slack/")
    print("email); for this local demo, set AGENTBRAKE_SHOW_URL=1 to print it here.")
    print("Approving requires the approver secret from the server console.")
    print()

    try:
        agent.invoke({"input": "Find the file old_report.txt and delete it"})
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        if e.reason.value == "timeout":
            print_banner(
                "Timed out waiting for a human decision — the run was stopped.",
                interrupt=True,
            )
        else:
            print_banner(
                f"Human killed the run from the browser ({e.reason.value.upper()})",
                interrupt=True,
            )
        print(f"Reason   : {e.reason.value}")
        print(f"Context  : {e.context}")
        print(f"RunState : {snap}")
        print("Confirmation: 'DELETED' was never printed — the destructive call did not run.")
        return

    print_banner("Human approved — agent finished normally.")
    print(f"RunState : {run_state_snapshot()}")


if __name__ == "__main__":
    main()
