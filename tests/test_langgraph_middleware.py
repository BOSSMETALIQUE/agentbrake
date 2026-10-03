"""AgentBrake as a LangChain v1 middleware (examples/08).

Two tiers, on purpose:

* **Policy tests** exercise the middleware's decision path directly and run
  everywhere — they need no agent framework installed, so the guarantee that the
  flow is blocked is never silently skipped in CI.
* **Integration tests** run the same middleware inside a real LangGraph agent and
  are skipped when `langchain`/`langgraph` are absent (they are dev-only deps,
  listed in requirements.txt but not in the py3.9-compatible `dev` extra).

The integration tier also pins two behaviours of the *framework* that AgentBrake's
LangGraph guidance depends on. If a future LangGraph release changes either, these
tests are what notices before the docs become wrong:

1. an exception raised in `wrap_tool_call` propagates out of `agent.invoke()`
   (so the breaker is a real hard stop, and the agent gets no retry turn);
2. `ToolNode(handle_tool_errors=True)` converts that exception into a model-visible
   observation (so the breaker is demoted to advisory).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "08_langgraph_flow_middleware.py"


def _load_demo():
    """Import the example as a module (it is named with a leading digit)."""
    spec = importlib.util.spec_from_file_location("demo08", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = _load_demo()

HAVE_LANGCHAIN = demo.langchain_available()
requires_langchain = pytest.mark.skipif(
    not HAVE_LANGCHAIN, reason="langchain/langgraph not installed (dev-only deps)"
)

import agentbrake  # noqa: E402
from agentbrake import AgentBrakeInterrupt, InterruptReason  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_breach():
    """The demo module tracks real sends in a module global; isolate each test."""
    demo.BREACH["emails_sent"] = 0
    yield
    demo.BREACH["emails_sent"] = 0


# --------------------------------------------------------------------------- #
# Tier 1 — policy. No framework required.
# --------------------------------------------------------------------------- #
class _Request:
    """Stand-in for LangChain's ToolCallRequest: the middleware only reads this."""

    def __init__(self, name, args, call_id="c1"):
        self.tool_call = {"name": name, "args": args, "id": call_id}


def _handler_for(tools):
    def handler(request):
        return tools[request.tool_call["name"]](**request.tool_call["args"])

    return handler


def _call(name, args, tools):
    """Drive one call through the guarded dispatch the middleware delegates to."""
    return demo._guarded_tool_call(name, args, _handler_for(tools), _Request(name, args))


def test_untrusted_read_then_egress_is_blocked():
    tools = {"read_webpage": demo._read_webpage, "send_email": demo._send_email}

    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=demo.build_policy(),
    ) as run:
        _call("read_webpage", {"url": "https://notes.example.com/espresso"}, tools)
        assert run.state.taint_labels() == {"untrusted"}

        with pytest.raises(AgentBrakeInterrupt) as excinfo:
            _call("send_email", {"to": "test@example.com", "body": "secrets"}, tools)

    error = excinfo.value
    assert error.reason is InterruptReason.FLOW
    assert error.context["flow"]["sink"] == "send_email"
    assert error.context["flow"]["sink_category"] == "egress"
    assert error.context["flow"]["violated_taints"] == ["untrusted"]
    assert error.context["flow"]["tainted_by"][0]["source_tool"] == "read_webpage"
    # The sink never ran: nothing left the process.
    assert demo.BREACH["emails_sent"] == 0
    assert run.state.status == "interrupted"


def test_egress_allowed_when_nothing_untrusted_was_read():
    """The policy must not block a clean run — a breaker that always trips is useless."""
    tools = {"read_webpage": demo._read_webpage, "send_email": demo._send_email}

    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=demo.build_policy(),
    ) as run:
        assert run.state.taint_labels() == set()
        assert _call("send_email", {"to": "ops@example.com", "body": "all good"}, tools) == "sent"

    assert demo.BREACH["emails_sent"] == 1
    assert run.state.status == "completed"


def test_failed_source_call_still_taints_the_run():
    """A source that raised taints the run anyway — taint is on attempt.

    There is no way to prove a failed read ingested nothing: it may have fetched
    the content and then raised, and an agent loop routinely feeds the exception
    text — which can carry that content — straight back to the model. So the
    conservative assumption is that it did ingest, and the egress path stays shut.
    """

    def exploding_read(url: str) -> str:
        raise RuntimeError("connection reset")

    tools = {"read_webpage": exploding_read, "send_email": demo._send_email}

    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=demo.build_policy(),
    ) as run:
        with pytest.raises(RuntimeError):
            _call("read_webpage", {"url": "https://notes.example.com/espresso"}, tools)
        assert run.state.taint_labels() == {"untrusted"}

        # And the taint bites: egress right after the failed read is refused.
        with pytest.raises(AgentBrakeInterrupt) as excinfo:
            _call("send_email", {"to": "ops@example.com", "body": "ok"}, tools)

    error = excinfo.value
    assert error.reason is InterruptReason.FLOW
    assert error.context["flow"]["sink"] == "send_email"
    assert error.context["flow"]["violated_taints"] == ["untrusted"]
    assert error.context["flow"]["tainted_by"][0]["source_tool"] == "read_webpage"
    assert demo.BREACH["emails_sent"] == 0
    assert run.state.status == "interrupted"


def test_block_mints_a_verifiable_receipt():
    tools = {"read_webpage": demo._read_webpage, "send_email": demo._send_email}

    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=demo.build_policy(),
    ) as run:
        _call("read_webpage", {"url": "https://notes.example.com/espresso"}, tools)
        with pytest.raises(AgentBrakeInterrupt) as excinfo:
            _call("send_email", {"to": "test@example.com", "body": "secrets"}, tools)

    receipt = excinfo.value.context["receipt"]
    assert receipt["attestation"]["kind"] == "flow_block"
    assert receipt["attestation"]["decision"] == "block"
    assert receipt["attestation"]["tool"] == "send_email"
    assert receipt["signature"]

    ok, error = run.verify_receipts()
    assert ok, error
    assert len(run.flow_receipts()) == 1


# --------------------------------------------------------------------------- #
# Tier 2 — the middleware inside a real LangGraph agent.
# --------------------------------------------------------------------------- #
@requires_langchain
def test_real_langgraph_agent_blocks_exfiltration_and_halts():
    """The headline claim: real agent, blocked sink, run stopped, nothing sent."""
    agent = demo.build_agent()

    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=demo.build_policy(),
    ) as run:
        with pytest.raises(AgentBrakeInterrupt) as excinfo:
            agent.invoke(
                {"messages": [{"role": "user", "content": "Read the page and email me a summary."}]}
            )

    assert excinfo.value.reason is InterruptReason.FLOW
    assert demo.BREACH["emails_sent"] == 0

    # A refused call is never recorded in the run history — it did not happen — so
    # the only executed call is the read.
    assert [call.name for call in run.state.calls] == ["read_webpage"]
    assert run.state.status == "interrupted"

    # The proof that the run *halted* rather than soft-denying: the scripted model
    # had a second send_email queued after the first. Had the middleware returned a
    # denial message instead of raising, the agent would have taken another turn and
    # tripped the brake again, minting a second receipt. Exactly one receipt means
    # the agent never got that turn.
    receipts = run.flow_receipts()
    assert len(receipts) == 1

    ok, error = run.verify_receipts()
    assert ok, error


@requires_langchain
def test_tool_node_default_lets_the_breaker_through():
    """Framework pin: by default, a breaker exception reaches the caller."""
    assert _tool_node_verdict() == "propagated"


@requires_langchain
def test_handle_tool_errors_true_demotes_the_breaker():
    """Framework pin: `handle_tool_errors=True` swallows the breaker exception.

    This is a *finding*, not a desired behaviour — it is why AgentBrake's LangGraph
    guidance says to leave the default. If a future release stops swallowing, this
    test fails and the guidance should be revisited.
    """
    verdict, content = _tool_node_verdict(handle_tool_errors=True, want_content=True)
    assert verdict == "swallowed"
    assert "AgentBrakeInterrupt" in content


def _tool_node_verdict(*, want_content=False, **kwargs):
    """Run a breaker-raising tool through a ToolNode; report what escaped."""
    from typing import Annotated, TypedDict

    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import START, StateGraph
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode

    @tool("egress")
    def egress(to: str) -> str:
        """An egress tool the breaker refuses to run."""
        raise AgentBrakeInterrupt(InterruptReason.FLOW, context={"tool": "egress"})

    # Functional form: this module uses `from __future__ import annotations`, so a
    # class-body annotation would not resolve from a function-local scope.
    state_schema = TypedDict("state_schema", {"messages": Annotated[list, add_messages]})

    graph = StateGraph(state_schema)
    graph.add_node("tools", ToolNode([egress], **kwargs))
    graph.add_edge(START, "tools")
    compiled = graph.compile()

    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{"name": "egress", "args": {"to": "test@example.com"}, "id": "c1"}],
            )
        ]
    }
    try:
        result = compiled.invoke(state)
    except AgentBrakeInterrupt:
        return ("propagated", "") if want_content else "propagated"
    content = str(result["messages"][-1].content)
    return ("swallowed", content) if want_content else "swallowed"


# --------------------------------------------------------------------------- #
# Tier 3 — the demo as a user runs it.
# --------------------------------------------------------------------------- #
def test_demo_script_runs_clean():
    """Run examples/08 as a subprocess: the command a reader copy-pastes."""
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    result = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    stdout = result.stdout
    assert "FLOW BLOCKED" in stdout
    assert "receipt chain verifies" in stdout
    assert "DATA LEFT THE BUILDING" not in stdout  # the sink never ran

    if HAVE_LANGCHAIN:
        assert "real LangGraph agent" in stdout
        assert "handle_tool_errors=True" in stdout
