"""Compliance reports: turn a verified receipt bundle into an auditor-readable document.

A receipts export proves *that* enforcement happened; this module explains
*what* happened, in language a CISO or auditor can act on: which attacks were
blocked autonomously, which runs a human stopped or approved, over what
period — each event referencing the cryptographic receipt that proves it.

Two design rules keep the report honest:

* **It is generated from the export bundle, never from the raw database**, and
  the bundle is verified first. The verification verdict — including a failed
  one — leads the report. A report over unverified evidence would be exactly
  the security theater this project refuses to ship.
* **Structured first, rendered second.** :func:`build_report` produces plain
  data (testable, reusable); :func:`render_markdown` turns it into the
  document. Nothing appears in the rendering that is not in the data.

Timestamps are the signer's own clock (stated in the report footer); period
filtering therefore filters on self-reported times. Verification always covers
the whole chain regardless of the period shown.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

REPORT_FORMAT_VERSION = "1"

# Human-facing labels for interrupt reasons (keys are the signed `reason` field).
_REASON_LABELS = {
    "flow": "Forbidden data flow (e.g. prompt-injection -> exfiltration)",
    "escalation": "Tool outside the allow-list",
    "loop": "Runaway loop / retry storm",
    "budget": "Budget ceiling reached",
    "timeout": "Human validation timed out",
    "delegation": "Delegated-privilege misuse (out-of-scope or expired mandate)",
}

# Kinds of autonomous blocks vs. delegation lifecycle events vs. human decisions.
_BLOCK_KINDS = {"flow_block", "delegation_block"}
_DELEGATION_LIFECYCLE_KINDS = {"delegation_grant", "delegation_accept", "delegation_reject"}


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _event_time(attestation: Dict[str, Any]) -> Optional[str]:
    """The moment the event became final: human decision time, or block time."""
    return (
        attestation.get("decided_at")
        or attestation.get("blocked_at")
        or attestation.get("recorded_at")
    )


def _within(ts: Optional[str], period: Tuple[Optional[datetime], Optional[datetime]]) -> bool:
    start, end = period
    parsed = _parse_ts(ts)
    if parsed is None:
        return True  # undated events stay visible rather than silently dropped
    if start and parsed < start:
        return False
    if end and parsed > end:
        return False
    return True


def _evidence_ref(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {"seq": entry["seq"], "entry_hash": entry["entry_hash"]}


def build_report(
    bundle: Dict[str, Any],
    verification: Dict[str, Any],
    *,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
    source_name: str = "receipts export",
) -> Dict[str, Any]:
    """Assemble the structured report from a bundle and its verification result.

    ``verification`` is the report from :func:`agentbrake.export.verify_export`
    — run it first, with pinned keys if you have them; its verdict is embedded
    verbatim, pass or fail.
    """
    period = (period_start, period_end)
    entries = bundle.get("entries") or []

    events: List[Dict[str, Any]] = []
    for entry in entries:
        try:
            attestation = json.loads(entry["attestation_json"])
        except (KeyError, json.JSONDecodeError):
            continue
        when = _event_time(attestation)
        if not _within(when, period):
            continue
        events.append(
            {
                "when": when,
                "reason": attestation.get("reason") or "unknown",
                "decision": attestation.get("decision"),
                "kind": attestation.get("kind") or "human_decision",
                "tool": attestation.get("tool"),
                "run_id": attestation.get("run_id"),
                "agent_id": attestation.get("agent_id"),
                "pending_seconds": attestation.get("pending_seconds"),
                "flow": attestation.get("flow"),
                "delegation": attestation.get("delegation"),
                "evidence": _evidence_ref(entry),
            }
        )

    flow_blocks = [e for e in events if e["kind"] == "flow_block"]
    # A human overriding a flow block is its own category. Left in the generic
    # approval bucket it reads as routine sign-off, when it is the event an
    # auditor most needs to find: an exfiltration the engine caught and a
    # person let through anyway.
    flow_overrides = [e for e in events if e["kind"] == "flow_override"]
    delegation_blocks = [e for e in events if e["kind"] == "delegation_block"]
    delegation_lifecycle = [
        e for e in events if e["kind"] in _DELEGATION_LIFECYCLE_KINDS
    ]
    human = [
        e for e in events
        if e["kind"] not in _BLOCK_KINDS
        and e["kind"] not in _DELEGATION_LIFECYCLE_KINDS
        and e["kind"] != "flow_override"
    ]
    kills = [e for e in human if e["decision"] == "kill"]
    approvals = [e for e in human if e["decision"] == "approve"]

    by_reason: Dict[str, int] = {}
    for e in events:
        by_reason[e["reason"]] = by_reason.get(e["reason"], 0) + 1

    decision_times = [
        e["pending_seconds"]
        for e in human
        if isinstance(e.get("pending_seconds"), (int, float))
    ]

    statement = (bundle.get("head") or {}).get("statement") or {}
    return {
        "format_version": REPORT_FORMAT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_name,
        "chain_id": bundle.get("chain_id"),
        "chain_length": len(entries),
        "tree_root": statement.get("tree_root"),
        "period": {
            "start": period_start.isoformat() if period_start else None,
            "end": period_end.isoformat() if period_end else None,
        },
        "verification": verification,
        "events_in_period": len(events),
        "summary": {
            "autonomous_blocks": len(flow_blocks) + len(delegation_blocks),
            "human_kills": len(kills),
            "human_approvals": len(approvals),
            "flow_overrides": len(flow_overrides),
            "delegations_granted": len(
                [e for e in delegation_lifecycle if e["kind"] == "delegation_grant"]
            ),
            "delegations_rejected": len(
                [e for e in delegation_lifecycle if e["kind"] == "delegation_reject"]
            ),
            "by_reason": by_reason,
            "mean_decision_seconds": (
                round(sum(decision_times) / len(decision_times), 1)
                if decision_times
                else None
            ),
            "max_decision_seconds": max(decision_times) if decision_times else None,
        },
        "flow_blocks": flow_blocks,
        "flow_overrides": flow_overrides,
        "delegation_blocks": delegation_blocks,
        "delegation_lifecycle": delegation_lifecycle,
        "human_decisions": human,
    }


# ----- rendering ------------------------------------------------------------

def _fmt_when(ts: Optional[str]) -> str:
    parsed = _parse_ts(ts)
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC") if parsed else "(no timestamp)"


def _fmt_ref(evidence: Dict[str, Any]) -> str:
    return f"receipt #{evidence['seq']} (`{evidence['entry_hash'][:16]}...`)"


def _flow_narrative(event: Dict[str, Any]) -> str:
    """One plain-language sentence describing a blocked flow."""
    flow = event.get("flow") or {}
    sink = flow.get("sink") or event.get("tool") or "an egress tool"
    sources = flow.get("tainted_by") or []
    if sources:
        origins = ", ".join(
            f"`{s.get('source_tool')}` (call #{s.get('call_index')})" for s in sources
        )
        return (
            f"The agent ingested untrusted content via {origins}, then attempted "
            f"to call `{sink}`. AgentBrake blocked the call before it executed."
        )
    return f"A forbidden flow into `{sink}` was blocked before it executed."


def _delegation_narrative(event: Dict[str, Any]) -> str:
    """One plain-language sentence describing a blocked delegated action."""
    d = event.get("delegation") or {}
    delegatee = d.get("delegatee") or "the delegated agent"
    delegator = d.get("delegator") or "another agent"
    tool = event.get("tool") or "a tool"
    scope = ", ".join(f"`{t}`" for t in (d.get("allowed_tools") or [])) or "(empty)"
    if d.get("violation") == "expired":
        return (
            f"Agent `{delegatee}` attempted `{tool}` after its delegated mandate "
            f"from `{delegator}` had expired. AgentBrake blocked the call before "
            "it executed."
        )
    return (
        f"Agent `{delegatee}`, acting under a delegation from `{delegator}`, "
        f"attempted `{tool}` — outside its delegated scope ({scope}). "
        "AgentBrake blocked the call before it executed."
    )


def render_markdown(report: Dict[str, Any]) -> str:
    """Render the structured report as a self-contained Markdown document."""
    v = report["verification"]
    summary = report["summary"]
    lines: List[str] = []
    out = lines.append

    out("# AgentBrake enforcement report")
    out("")
    period = report["period"]
    if period["start"] or period["end"]:
        out(f"**Period:** {period['start'] or 'beginning'} to {period['end'] or 'now'}")
    out(f"**Generated:** {_fmt_when(report['generated_at'])}  ")
    out(f"**Source:** {report['source']}  ")
    out(f"**Chain:** `{report['chain_id']}` — {report['chain_length']} receipt(s), "
        f"Merkle root `{str(report['tree_root'])[:16]}...`")
    out("")

    # --- verification verdict, pass or fail, before anything else ---
    if v["ok"]:
        keys = ", ".join(f"`{k}`" for k in v["public_keys"]) or "(none)"
        pin_note = (
            "pinned by the report author"
            if v["keys_pinned"]
            else "embedded in the bundle — confirm out-of-band"
        )
        out("## Evidence integrity: VERIFIED")
        out("")
        out(
            f"All {v['entry_count']} receipt(s) verified cryptographically "
            f"(Ed25519, key id(s) {keys}, {pin_note}): every record is authentic, "
            "unmodified, and the log is complete and ordered as signed."
        )
        if not v["third_party_verifiable"]:
            out("")
            out(
                "> **Caution:** these receipts are NOT third-party verifiable "
                "(legacy HMAC signing or unsigned head). Treat this report as an "
                "internal integrity check, not independent proof."
            )
    else:
        failed = [c["name"] for c in v["checks"] if not c["ok"]]
        out("## Evidence integrity: VERIFICATION FAILED")
        out("")
        out(
            "> **WARNING: the receipts backing this report did NOT verify** "
            f"(failed check(s): {', '.join(failed)}). Findings below cannot be "
            "trusted until the evidence is re-established."
        )
    out("")

    # --- executive summary ---
    out("## Executive summary")
    out("")
    out(
        f"Over the covered period, AgentBrake recorded "
        f"**{report['events_in_period']} enforcement event(s)**:"
    )
    out("")
    out(f"- **{summary['autonomous_blocks']}** attack flow(s) blocked automatically")
    out(f"- **{summary['human_kills']}** run(s) stopped by a human reviewer")
    out(f"- **{summary['human_approvals']}** interrupt(s) reviewed and approved by a human")
    if summary["mean_decision_seconds"] is not None:
        out(
            f"- Human response time: mean **{summary['mean_decision_seconds']}s**, "
            f"max **{summary['max_decision_seconds']}s**"
        )
    out("")
    if summary["by_reason"]:
        out("| Risk detected | Events |")
        out("|---|---|")
        for reason, count in sorted(summary["by_reason"].items(), key=lambda kv: -kv[1]):
            out(f"| {_REASON_LABELS.get(reason, reason)} | {count} |")
        out("")

    # --- blocked attacks ---
    if report["flow_blocks"] or report["delegation_blocks"]:
        out("## Attacks blocked automatically")
        out("")
        for event in report["flow_blocks"] + report["delegation_blocks"]:
            out(f"### {_fmt_when(event['when'])} — `{event['tool']}` blocked")
            out("")
            narrative = (
                _delegation_narrative(event)
                if event["kind"] == "delegation_block"
                else _flow_narrative(event)
            )
            out(narrative)
            out("")
            if event.get("run_id"):
                agent = f", agent `{event['agent_id']}`" if event.get("agent_id") else ""
                out(f"- Run: `{event['run_id']}`{agent}")
            out(f"- Evidence: {_fmt_ref(event['evidence'])}")
            out("")

    # --- delegation lifecycle ---
    if report["delegation_lifecycle"]:
        out("## Delegation activity")
        out("")
        out(
            "Signed delegation tokens carry the user's original intent across "
            "agents; each grant/acceptance below embeds the full token in its "
            "receipt, re-verified by `agentbrake verify` (`delegation_tokens` check)."
        )
        out("")
        out("| When | Event | From -> To | Delegated scope | Evidence |")
        out("|---|---|---|---|---|")
        for event in report["delegation_lifecycle"]:
            d = event.get("delegation") or {}
            label = event["kind"].replace("delegation_", "")
            scope = ", ".join(f"`{t}`" for t in (d.get("allowed_tools") or [])) or "-"
            out(
                f"| {_fmt_when(event['when'])} "
                f"| {label} "
                f"| `{d.get('delegator')}` -> `{d.get('delegatee')}` "
                f"| {scope} "
                f"| {_fmt_ref(event['evidence'])} |"
            )
        out("")

    # --- human decisions ---
    if report["human_decisions"]:
        out("## Human decisions")
        out("")
        out("| When | Risk | Decision | Tool | Response time | Evidence |")
        out("|---|---|---|---|---|---|")
        for event in report["human_decisions"]:
            pending = (
                f"{event['pending_seconds']}s"
                if isinstance(event.get("pending_seconds"), (int, float))
                else "-"
            )
            out(
                f"| {_fmt_when(event['when'])} "
                f"| {_REASON_LABELS.get(event['reason'], event['reason'])} "
                f"| **{event['decision']}** "
                f"| `{event['tool']}` "
                f"| {pending} "
                f"| {_fmt_ref(event['evidence'])} |"
            )
        out("")

    if not (
        report["flow_blocks"]
        or report["delegation_blocks"]
        or report["delegation_lifecycle"]
        or report["human_decisions"]
    ):
        out("_No enforcement events in the covered period._")
        out("")

    # --- evidence appendix ---
    out("## Verifying this report")
    out("")
    out(
        "Every event above references a signed receipt. To re-verify the "
        "evidence independently (offline, public key only):"
    )
    out("")
    out("```")
    out("agentbrake verify <bundle.json> --public-key <hex-obtained-out-of-band>")
    out("agentbrake prove --receipts <ledger> --seq <N>   # single-receipt proof")
    out("```")
    out("")
    out("### Scope and limits of the evidence")
    out("")
    out(
        "- Receipts prove **enforcement decisions and their recorded inputs** — "
        "signed, complete, and unmodified under the stated key. They do not "
        "prove ground truth about agent activity outside the guarded dispatch."
    )
    out(
        "- **Timestamps are self-reported** by the signing process's clock; "
        "period filtering relies on them."
    )
    out(
        "- The private-key holder could regenerate history before it is "
        "anchored; pin export heads (`--expect-head`, `--consistent-with`) "
        "across audits to close that window."
    )
    out("")
    return "\n".join(lines)
