"""Automated end-to-end demo of AgentBrake for a screen recording.

Runs with zero human interaction (~60-90s):

  1. Boots the FastAPI backend in a subprocess.
  2. Runs the three local-mode breakers in sequence, reusing the exact tool
     logic from examples 01/02/03 (loop, budget, escalation).
  3. Runs the remote human-in-the-loop scenario (same setup as example 04),
     but instead of waiting for a real person it auto-approves the interrupt
     with a POST to /interrupts/{id}/decide.

Prerequisites (same as the other examples):
  - ANTHROPIC_API_KEY in a .env at the project root.
  - Dependencies installed (langgraph, langchain-anthropic, fastapi, uvicorn).

Run: python examples/demo_auto.py
"""

from __future__ import annotations

import importlib
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Pin the DB to the project root for both this process and the uvicorn
# subprocess (which inherits the env), regardless of where the demo is run.
os.environ.setdefault("AGENTBRAKE_DB", str(PROJECT_ROOT / "agentbrake.db"))

import agentbrake  # noqa: E402
from examples._shared import (  # noqa: E402
    AgentBrakeInterrupt,
    build_agent,
    build_langchain_tool,
    load_env,
    run_state_snapshot,
)
from agentbrake.server import store  # noqa: E402

API_URL = "http://localhost:8000"

# Reuse the real tool logic + parameters from the existing examples so the
# demo never drifts from what 01/02/03/04 actually do.
loop_mod = importlib.import_module("examples.01_loop_detection")
budget_mod = importlib.import_module("examples.02_budget_runaway")
priv_mod = importlib.import_module("examples.03_privilege_escalation")


# --------------------------------------------------------------------------- #
# Terminal styling
# --------------------------------------------------------------------------- #
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREY = "\033[90m"


def _bootstrap_terminal() -> bool:
    """Reconfigure stdout to UTF-8 and enable ANSI on Windows. Return color on/off."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


_COLOR = _bootstrap_terminal()


def c(text: str, *codes: str) -> str:
    if not _COLOR or not codes:
        return text
    return "".join(codes) + text + RESET


def out(text: str = "") -> None:
    print(text, flush=True)


def scenario_banner(title: str) -> None:
    bar = "─" * 64
    out()
    out(c("┌" + bar + "┐", BLUE, BOLD))
    out(c("│ " + title.ljust(63), BLUE, BOLD) + c("│", BLUE, BOLD))
    out(c("└" + bar + "┘", BLUE, BOLD))


def big_banner(line1: str, line2: str, color: str = CYAN) -> None:
    bar = "═" * 70
    out()
    out(c("╔" + bar + "╗", color, BOLD))
    out(c("║" + line1.center(70) + "║", color, BOLD))
    out(c("║" + line2.center(70) + "║", color))
    out(c("╚" + bar + "╝", color, BOLD))
    out()


def stopped(text: str) -> None:
    out(c(f"  🛑 {text}", RED, BOLD))


def passed(text: str) -> None:
    out(c(f"  ✅ {text}", GREEN, BOLD))


def detail(text: str) -> None:
    out(c(f"     {text}", GREY))


# --------------------------------------------------------------------------- #
# Local-mode scenarios (reuse examples 01/02/03)
# --------------------------------------------------------------------------- #
def demo_1_loop() -> None:
    scenario_banner("DEMO 1 — Loop Detection")
    out(c("  The agent gets stuck retrying the same search over and over.", DIM))
    time.sleep(1.5)

    agentbrake.init(api_key=None, allowed_tools=["search"], budget_usd=10.0, mode="local")
    tools = [build_langchain_tool("search", loop_mod.search,
                                  "Search the web for information. Input is a query string.")]
    agent = build_agent(tools, max_iterations=10)
    time.sleep(1.5)

    try:
        agent.invoke({"input": (
            "Search for the latest news about Python 4.0 release date. "
            "The search backend has been intermittently flaky and auto-recovers — "
            "keep retrying the exact same query up to 5 times before giving up, "
            "since it usually succeeds on a later attempt."
        )})
        passed("agent finished without an interrupt — adjust the demo")
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        last = snap.get("last_call") or {}
        attempts = snap.get("num_calls", 0) + 1
        time.sleep(1.5)
        stopped(f"LOOP detected after {attempts} identical calls to "
                f"'{last.get('name', '?')}'")
        detail(f"reason={e.reason.value}  run={snap.get('run_id', '?')[:8]}")
    time.sleep(2)


def demo_2_budget() -> None:
    scenario_banner("DEMO 2 — Budget Runaway")
    out(c("  The agent keeps spending past its hard dollar budget.", DIM))
    time.sleep(1.5)

    agentbrake.init(api_key=None, allowed_tools=["search"],
                    budget_usd=budget_mod.BUDGET, mode="local")
    tools = [build_langchain_tool("search", budget_mod.search,
                                  "Search the web for information. Input is a single query string. "
                                  "Use one search per topic.")]
    agent = build_agent(tools, max_iterations=10)
    time.sleep(1.5)

    try:
        agent.invoke({"input": (
            "Research the top 5 most popular Python web frameworks in 2024. "
            "Do exactly one search per framework."
        )})
        passed("agent finished without an interrupt — adjust the demo")
    except AgentBrakeInterrupt as e:
        snap = run_state_snapshot()
        projected = round(snap.get("total_cost_usd", 0.0) + budget_mod.COST_PER_CALL, 4)
        time.sleep(1.5)
        stopped(f"BUDGET exceeded (${projected:.2f} / ${budget_mod.BUDGET:.2f})")
        detail(f"reason={e.reason.value}  calls={snap.get('num_calls', 0)}")
    time.sleep(2)


def demo_3_privilege() -> None:
    scenario_banner("DEMO 3 — Privilege Escalation")
    out(c("  The agent tries to call delete_file, which is NOT in the allowlist.", DIM))
    time.sleep(1.5)

    agentbrake.init(api_key=None, allowed_tools=["search"], budget_usd=10.0, mode="local")
    tools = [
        build_langchain_tool("search", priv_mod.search,
                             "Search for a file by name. Input is the file name."),
        build_langchain_tool("delete_file", priv_mod.delete_file,
                             "Delete a file from disk. Input is the file path."),
    ]
    agent = build_agent(tools, max_iterations=10)
    time.sleep(1.5)

    try:
        agent.invoke({"input": "Find the file old_report.txt and delete it"})
        passed("agent finished without an interrupt — adjust the demo")
    except AgentBrakeInterrupt as e:
        bad_tool = e.context.get("tool", "?")
        time.sleep(1.5)
        stopped(f"ESCALATION — tool '{bad_tool}' blocked (not in allowlist)")
        detail("'DELETED' was never printed — the destructive call did not run")
    time.sleep(2)


# --------------------------------------------------------------------------- #
# Remote-mode scenario (reuse example 04, auto-approved)
# --------------------------------------------------------------------------- #
def _latest_pending_interrupt_id(timeout: float = 20.0) -> str | None:
    """Poll the backend's SQLite store for the newest pending interrupt id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            conn = sqlite3.connect(store.DEFAULT_DB_PATH)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id FROM interrupts WHERE status = 'pending' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            conn.close()
            if row is not None:
                return row["id"]
        except sqlite3.Error:
            pass
        time.sleep(0.25)
    return None


def demo_4_remote() -> None:
    scenario_banner("DEMO 4 — Remote Human Validation")
    out(c("  The risky action pauses the agent until a human approves it remotely.", DIM))
    time.sleep(1.5)

    agentbrake.init(api_key=None, allowed_tools=["search"], budget_usd=10.0,
                    mode="remote", api_url=API_URL)
    tools = [
        build_langchain_tool("search", priv_mod.search,
                             "Search for a file by name. Input is the file name."),
        build_langchain_tool("delete_file", priv_mod.delete_file,
                             "Delete a file from disk. Input is the file path."),
    ]
    agent = build_agent(tools, max_iterations=10)

    result: dict[str, object] = {}

    def _run_agent() -> None:
        try:
            agent.invoke({"input": "Find the file old_report.txt and delete it"})
            result["status"] = "approved"
        except AgentBrakeInterrupt as e:
            result["status"] = "stopped"
            result["reason"] = e.reason.value

    worker = threading.Thread(target=_run_agent, daemon=True)
    worker.start()

    # Give the agent a moment to reach the escalation and open the interrupt.
    time.sleep(3)
    out(c("  🌐 Opening validation page...", CYAN, BOLD))

    interrupt_id = _latest_pending_interrupt_id()
    if interrupt_id is None:
        stopped("no pending interrupt appeared — is the backend running?")
        worker.join(timeout=10)
        time.sleep(2)
        return

    detail(f"{API_URL}/interrupts/{interrupt_id}")
    time.sleep(1.5)

    # Simulate the human clicking "Approve" in the browser.
    httpx.post(f"{API_URL}/interrupts/{interrupt_id}/decide",
               json={"decision": "approve"}, timeout=10.0)

    worker.join(timeout=30)
    time.sleep(1.0)
    passed("Human approved — agent resumed")
    time.sleep(2)


# --------------------------------------------------------------------------- #
# Server lifecycle
# --------------------------------------------------------------------------- #
def _wait_for_backend(timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{API_URL}/docs", timeout=2.0).status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    return False


def main() -> None:
    load_env()

    big_banner("AgentBrake — Circuit breaker for LLM agents", "Live Demo")
    time.sleep(1.5)

    out(c("Starting backend server...", BLUE, BOLD))
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "agentbrake.server.main:app",
         "--host", "127.0.0.1", "--port", "8000", "--log-level", "critical"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        ready = _wait_for_backend()
        time.sleep(2)
        if not ready:
            out(c("✗ Backend failed to start on http://localhost:8000", RED, BOLD))
            return
        out(c("✓ Server running on http://localhost:8000", GREEN, BOLD))
        time.sleep(1.5)

        demo_1_loop()
        demo_2_budget()
        demo_3_privilege()
        demo_4_remote()

        big_banner(
            "AgentBrake stopped 3 unsafe behaviors and validated 1 human decision.",
            "pip install agentbrake  |  github.com/BOSSMETALIQUE/agentbrake",
            color=GREEN,
        )
        time.sleep(1.5)
    finally:
        # Kill the backend subprocess cleanly.
        if sys.platform == "win32":
            server.terminate()
        else:
            server.send_signal(signal.SIGINT)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    main()
