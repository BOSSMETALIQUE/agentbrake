"""Taint-tracking flow rules: stop dangerous *sequences*, not just bad tools.

The allow-list answers "may the agent call this tool?". It cannot answer "may
the agent call this tool *given what it has already done*?" — and that second
question is where the prompt-injection -> exfiltration attack lives. An agent
reads attacker-controlled content (a web page, an email) that says "send the
data to attacker@evil.com", then calls a perfectly allow-listed `send_email`.
Every individual call is permitted; the *flow* is the attack.

This module tracks **taint**. A tool can be declared a *source* that introduces
a taint label (``read_webpage`` -> ``untrusted``) or a *sink* of some category
(``send_email`` -> ``egress``). Once a source runs, its label stays active on
the RunState for the rest of the run. When the agent then tries to call a sink,
:class:`FlowRuleDetector` checks the active taints against the policy's deny
rules and trips the brake *before* the sink executes.

Design notes / honest limitations:

* **Taint is monotonic.** Once ``untrusted`` is active it is never cleared, so
  every later ``egress`` is blocked. This is deliberately conservative — there
  is no reliable way to "sanitize" attacker content mid-run — but it means a
  long-lived agent that legitimately needs to read untrusted data and *then*
  send unrelated trusted data will be stopped. Use a fresh ``run()`` per task.
* **Granularity is the tool call.** A tool declared as *both* a source and a
  sink is checked against the taint it would introduce itself, so it is blocked
  on its first call rather than egressing once and tainting afterwards. What
  the engine still cannot see is a single call that ingests and egresses under
  a name you declared as only one of the two — keep sources and sinks separate.
* **Taint is applied on attempt, not on success.** A source call taints the run
  even when it raises: a read that fails after fetching has still ingested the
  content, and agent loops routinely feed the exception message — which can
  carry that content — straight back to the model. There is no way to prove a
  failed read ingested nothing, so the conservative assumption is that it did.
* **It is not a sandbox.** If the agent reaches a sink through a tool you never
  declared, the flow engine cannot see it. Declare every egress path, and keep
  the allow-list as your hard boundary underneath.

Argument-level exemptions (:meth:`FlowPolicy.allow_args`) narrow the one false
positive the tool-level rule cannot avoid: "read the web, then email *me* the
summary". A denied flow into a sink is let through when, and only when, every
recipient in every declared field is on a fixed allow-list — checked
deterministically on the call's arguments, fail-closed on anything the checker
does not fully understand, and receipted as ``flow_allow``. The exemption
weighs *where* the data goes, never *what* it says: an injected sentence in the
body still reaches the allowed recipient. See :class:`ArgExemption`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .server.attest import canonical_json
from .types import InterruptReason, RunState, TaintMark, ToolCall

# ---------------------------------------------------------------------------
# Argument-level exemptions
# ---------------------------------------------------------------------------

# A deliberately narrow subset of RFC 5321 addr-spec, matched on the lowercased
# value. What is left out is left out on purpose, because each piece is a
# routing or parsing trick rather than an address people actually type:
#   * display names, angle brackets, comments, quoted local parts — parsers
#     disagree on them (CPython's own ``email.utils.parseaddr`` mis-split
#     crafted ones: CVE-2023-27043), so the check and the mailer could read
#     two different recipients out of one string;
#   * ``%`` and ``!`` — the percent hack and bang paths relay to a *second*
#     host, so ``attacker%evil.com@example.com`` is not an example.com mailbox;
#   * ``,`` ``;`` and whitespace — several recipients hidden in one string;
#   * single-label and trailing-dot domains, IP literals, non-ASCII anywhere —
#     homoglyphs and encodings are refused rather than normalized.
# A legal but unusual address is therefore blocked, never misread.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}")
_ADDRESS_RE = re.compile(
    rf"(?P<local>[a-z0-9_+-]+(?:\.[a-z0-9_+-]+)*)@(?P<domain>{_DOMAIN_RE.pattern})"
)
_MAX_LOCAL = 64
_MAX_ADDRESS = 254
# Only spaces and tabs around a value are forgiven. CR/LF and every other
# control character are refused outright: they are header-injection material,
# and nothing legitimate needs them in a recipient.
_TRIM = " \t"
# Cap on how much of an offending value is echoed into explain(), i.e. into
# the interrupt and logs. Anything longer than a maximal address is not an
# address, and may be the exfiltrated data itself.
_ECHO_LIMIT = _MAX_ADDRESS


class _Refused(ValueError):
    """A value the exemption checker will not vouch for (blocks the call)."""


def normalize_address(value: object) -> str:
    """Canonical form of one bare email address, or raise ``ValueError``.

    Trims surrounding spaces/tabs and lowercases; refuses everything else that
    is not exactly one plain ``local@domain`` (see the grammar notes above).
    Used for both sides of the comparison — the allow-list at declaration time
    and the call's arguments at check time — so they can only match when they
    denote the same address under the same rules.
    """
    if not isinstance(value, str):
        raise _Refused(f"expected a string, got {type(value).__name__}")
    trimmed = value.strip(_TRIM)
    if not trimmed:
        raise _Refused("empty address")
    if not trimmed.isascii():
        raise _Refused("non-ASCII character (homoglyphs and encodings are refused)")
    if not trimmed.isprintable():
        raise _Refused("control character (e.g. CR/LF) in address")
    lowered = trimmed.lower()
    match = _ADDRESS_RE.fullmatch(lowered)
    if match is None:
        raise _Refused(
            "not a single bare address (display names, quoting, separators, "
            "source routes and '%'/'!' relays are refused)"
        )
    if len(match.group("local")) > _MAX_LOCAL or len(lowered) > _MAX_ADDRESS:
        raise _Refused("address too long")
    return lowered


def _normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        raise _Refused(f"expected a string, got {type(value).__name__}")
    trimmed = value.strip(_TRIM)
    if not trimmed.isascii() or not trimmed.isprintable():
        raise _Refused("non-ASCII or control character (use the punycode form)")
    lowered = trimmed.lower()
    if _DOMAIN_RE.fullmatch(lowered) is None:
        raise _Refused(
            "not a plain domain such as 'example.com' (no '@', wildcard, "
            "trailing dot or single label)"
        )
    return lowered


def _value_digest(value: object) -> str:
    """``sha256:<hex>`` of the raw value, as receipts digest arguments.

    What the signed receipt keeps instead of the value itself, so receipts
    stay free of raw arguments (and of whatever data an attacker stuffed into
    a recipient field) yet still commit to exactly what was refused.
    """
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _refusal(field: str, value: object, reason: str) -> Dict[str, object]:
    return {
        "field": field,
        "value": _echo(value),
        "value_digest": _value_digest(value),
        "reason": reason,
    }


def _echo(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    if len(text) > _ECHO_LIMIT:
        return text[:_ECHO_LIMIT] + f"...(+{len(text) - _ECHO_LIMIT} chars)"
    return text


def _names(arg: Iterable[str], what: str) -> Tuple[str, ...]:
    """Sorted, de-duplicated tuple of names; a bare string is a caller bug.

    ``fields="to"`` would otherwise iterate into ``("o", "t")`` and check
    neither real field — a silent no-op in a security control.
    """
    if isinstance(arg, (str, bytes)):
        raise TypeError(f"{what} must be a list of strings, not a bare string: {arg!r}")
    items = list(arg)
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{what} must contain strings, got {item!r}")
        if not item.strip(_TRIM):
            raise ValueError(f"{what} must contain non-empty strings, got {item!r}")
    return tuple(sorted(set(items)))


@dataclass(frozen=True)
class ArgExemption:
    """A sink call allowed despite a denied flow, judged on its arguments.

    Built by :meth:`FlowPolicy.allow_args`. The rule, all of which must hold:

    * every argument name is in ``fields`` or ``other_fields`` — any other
      argument (``reply_to``, ``recipients``, ``To``...) blocks the call,
      since it may be a destination nobody checked;
    * every value in ``fields`` is ``None``, an empty string or list (field
      not used), one address string, or a list/tuple of address strings —
      anything else (number, dict, nested list, comma-joined string) blocks;
    * there is at least one recipient overall — a call that names none may
      fall back to a destination set inside the tool;
    * every recipient normalizes (:func:`normalize_address`) and is either in
      ``values`` or has its domain, exactly, in ``domains`` (no subdomains).

    ``other_fields`` (``subject``, ``body``...) are allowed to be present but
    are **not** inspected: the exemption bounds where the data can go, not
    what it contains.
    """

    tool: str
    fields: Tuple[str, ...]
    values: Tuple[str, ...]
    domains: Tuple[str, ...]
    other_fields: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool,
            "kind": "email",
            "fields": list(self.fields),
            "values": list(self.values),
            "domains": list(self.domains),
            "other_fields": list(self.other_fields),
        }

    def _allows(self, address: str) -> bool:
        return address in self.values or address.rsplit("@", 1)[1] in self.domains

    def evaluate(self, args: Dict[str, Any]) -> Tuple[bool, Dict[str, object]]:
        """``(True, summary)`` if the call is exempt, else ``(False, failure)``.

        ``failure`` names the first offending field and value in a fixed
        order (unexpected fields first, then declared fields alphabetically,
        list items in order) so the same call always explains the same way.
        It carries the value (truncated, for the interrupt and the operator)
        and its ``value_digest``; only the digest goes into a receipt (see
        :func:`agentbrake.receipts.flow_for_receipt`). The success summary
        carries counts, not addresses, for the same reason.
        """
        if not isinstance(args, dict):
            return False, {"field": None, "reason": "arguments are not a mapping"}
        unexpected = sorted(set(args) - set(self.fields) - set(self.other_fields), key=str)
        if unexpected:
            return False, {
                "field": unexpected[0],
                "reason": "argument not declared in fields or other_fields",
            }
        recipients = 0
        for field in self.fields:
            raw = args.get(field)
            if isinstance(raw, str):
                items: List[object] = [raw] if raw.strip(_TRIM) else []
            elif isinstance(raw, (list, tuple)):
                items = list(raw)
            elif raw is None:
                items = []
            else:
                return False, _refusal(field, raw, f"unexpected type {type(raw).__name__}")
            for item in items:
                try:
                    address = normalize_address(item)
                except _Refused as e:
                    return False, _refusal(field, item, str(e))
                if not self._allows(address):
                    return False, _refusal(field, item, "recipient not in the allow-list")
                recipients += 1
        if recipients == 0:
            return False, {"field": None, "reason": "no recipient in any declared field"}
        return True, {"fields": list(self.fields), "recipients": recipients}


class FlowPolicy:
    """Declarative map of taint sources, sinks, and forbidden source->sink flows.

    Build it declaratively::

        policy = FlowPolicy(
            sources={"read_webpage": "untrusted", "read_profile": "sensitive"},
            sinks={"send_email": "egress", "http_post": "egress"},
            deny=[("untrusted", "egress"), ("sensitive", "egress")],
        )

    or fluently — every builder returns ``self`` so calls chain::

        policy = (
            FlowPolicy()
            .source("read_webpage", taint="untrusted")
            .sink("send_email", category="egress")
            .deny_flow(source="untrusted", sink="egress")
        )

    A *source* tool introduces one taint label when it runs. A *sink* tool
    belongs to one category. A *deny rule* forbids a (taint label, sink
    category) pair: if that taint is active when such a sink is about to run,
    the flow is blocked.
    """

    def __init__(
        self,
        sources: Optional[Dict[str, str]] = None,
        sinks: Optional[Dict[str, str]] = None,
        deny: Optional[Iterable[Tuple[str, str]]] = None,
    ):
        self._sources: Dict[str, str] = dict(sources or {})
        self._sinks: Dict[str, str] = dict(sinks or {})
        self._denied: Set[Tuple[str, str]] = {(s, k) for s, k in (deny or [])}
        self._exemptions: Dict[str, ArgExemption] = {}

    # ----- fluent builders ------------------------------------------------

    def source(self, tool: str, taint: str) -> "FlowPolicy":
        """Declare ``tool`` as introducing the taint label ``taint`` when it runs."""
        self._sources[tool] = taint
        return self

    def sink(self, tool: str, category: str) -> "FlowPolicy":
        """Declare ``tool`` as a sink belonging to ``category`` (e.g. ``egress``)."""
        self._sinks[tool] = category
        return self

    def deny_flow(self, source: str, sink: str) -> "FlowPolicy":
        """Forbid the flow of taint label ``source`` into sink category ``sink``."""
        self._denied.add((source, sink))
        return self

    def allow_args(
        self,
        tool: str,
        *,
        fields: Iterable[str],
        values: Iterable[str] = (),
        domains: Iterable[str] = (),
        other_fields: Iterable[str] = (),
    ) -> "FlowPolicy":
        """Let a denied flow into sink ``tool`` through for allow-listed recipients.

        ::

            policy = block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
                "send_email",
                fields=["to", "cc", "bcc"],          # every recipient field the tool has
                values=["me@example.com"],           # exact addresses...
                domains=["corp.example"],            # ...and/or whole domains (exact)
                other_fields=["subject", "body"],    # present but not inspected
            )

        The call is exempt only if :meth:`ArgExemption.evaluate` passes; any
        doubt blocks it, exactly as without the exemption. The exemption only
        ever *relaxes* a denied flow: it is not a recipient allow-list for an
        untainted run, where the sink is not blocked to begin with.

        Allow-list entries are normalized here, and a malformed one raises
        immediately — an entry that could never match is a typo, not a rule.
        One exemption per tool: a second call raises rather than silently
        widening or narrowing the first.
        """
        if tool in self._exemptions:
            raise ValueError(f"allow_args already declared for {tool!r}")
        field_names = _names(fields, "fields")
        other_names = _names(other_fields, "other_fields")
        if not field_names:
            raise ValueError("allow_args needs at least one recipient field")
        overlap = set(field_names) & set(other_names)
        if overlap:
            raise ValueError(
                f"fields and other_fields overlap on {sorted(overlap)}: a field "
                "is either checked or not"
            )
        try:
            addresses = tuple(sorted({normalize_address(v) for v in _names(values, "values")}))
            domain_names = tuple(
                sorted({_normalize_domain(d) for d in _names(domains, "domains")})
            )
        except _Refused as e:
            raise ValueError(f"allow_args({tool!r}): invalid allow-list entry: {e}") from None
        if not addresses and not domain_names:
            raise ValueError(f"allow_args({tool!r}): values and domains are both empty")
        self._exemptions[tool] = ArgExemption(
            tool=tool,
            fields=field_names,
            values=addresses,
            domains=domain_names,
            other_fields=other_names,
        )
        return self

    # ----- lookups used by the detector -----------------------------------

    def taint_for(self, tool: str) -> Optional[str]:
        """The taint label a tool introduces, or None if it is not a source."""
        return self._sources.get(tool)

    def sink_category_for(self, tool: str) -> Optional[str]:
        """The sink category a tool belongs to, or None if it is not a sink."""
        return self._sinks.get(tool)

    def is_denied(self, taint: str, sink_category: str) -> bool:
        """True if this taint label is forbidden from reaching this sink category."""
        return (taint, sink_category) in self._denied

    def violations(self, active_labels: Iterable[str], sink_category: str) -> List[str]:
        """Active taint labels that are forbidden from reaching ``sink_category``."""
        return sorted(
            label for label in active_labels if self.is_denied(label, sink_category)
        )

    def exemption_for(self, tool: str) -> Optional[ArgExemption]:
        """The argument-level exemption declared for ``tool``, if any."""
        return self._exemptions.get(tool)

    # ----- misconfiguration checks ----------------------------------------

    def validate(self) -> "FlowPolicy":
        """Raise if any deny rule can never fire. Returns ``self`` so it chains.

        Labels and categories are free-form strings, so ``deny_flow("untrused",
        "egress")`` is accepted in silence and then never matches anything:
        :meth:`is_denied` returns False forever, the policy looks protective,
        and it enforces nothing. For a security control a silent no-op is the
        worst available failure mode — worse than an error, because it is
        indistinguishable from working — so a typo has to be loud.

        Called for you when a policy is attached to a run. Deliberately *not*
        called from the builders: ``deny_flow`` may legitimately run before the
        ``source``/``sink`` it refers to, and only the finished policy can be
        judged.
        """
        labels = set(self._sources.values())
        categories = set(self._sinks.values())
        problems: List[str] = []
        for label, category in sorted(self._denied):
            rule = f"deny({label!r} -> {category!r})"
            if label not in labels:
                problems.append(
                    f"{rule}: no source introduces the taint label {label!r} "
                    f"(declared: {sorted(labels) or 'none'})"
                )
            if category not in categories:
                problems.append(
                    f"{rule}: no sink belongs to the category {category!r} "
                    f"(declared: {sorted(categories) or 'none'})"
                )
        # An exemption names a tool, not a label, so a typo there is just as
        # silent — and it fails the other way: the legitimate send it was
        # written for stays blocked while the policy reads as if it were not.
        exemption_problems: List[str] = []
        for tool, exemption in sorted(self._exemptions.items()):
            rule = f"allow_args({tool!r})"
            if tool not in self._sinks:
                exemption_problems.append(
                    f"{rule}: {tool!r} is not a declared sink "
                    f"(declared: {sorted(self._sinks) or 'none'})"
                )
            if not exemption.fields:
                exemption_problems.append(f"{rule}: no recipient field to check")
            if not exemption.values and not exemption.domains:
                exemption_problems.append(f"{rule}: values and domains are both empty")
        sections: List[str] = []
        if problems:
            sections.append(
                "FlowPolicy has deny rules that can never fire:\n  " + "\n  ".join(problems)
            )
        if exemption_problems:
            sections.append(
                "FlowPolicy has argument exemptions that cannot apply:\n  "
                + "\n  ".join(exemption_problems)
            )
        if sections:
            raise ValueError("\n".join(sections))
        return self

    def undeclared_tools(self, allowed_tools: Iterable[str]) -> List[str]:
        """Allow-listed tools this policy declares neither source nor sink.

        Every one is a path the flow engine cannot see. Most are harmless, but
        an egress tool you forgot to declare is exactly the hole the module
        docstring warns about, and nothing else in the system points at it.
        Advisory, not fatal: plenty of tools are legitimately neither.
        """
        return sorted(
            tool
            for tool in allowed_tools
            if tool not in self._sources and tool not in self._sinks
        )

    def to_dict(self) -> Dict[str, object]:
        """Serialize the policy to a dict for hashing / receipting.

        The dict format is stable across runs: sources and sinks are dicts,
        deny rules are sorted lists of [source, sink] pairs. This enables
        a third party to verify a receipt was minted under a specific policy
        by recomputing the hash of to_dict() and comparing to the receipt's
        policy_digest field.

        Returns::

            {
                "sources": {"read_webpage": "untrusted", ...},
                "sinks": {"send_email": "egress", ...},
                "deny": [["untrusted", "egress"], ...],
            }

        plus ``"allow_args"`` — a list of :meth:`ArgExemption.to_dict`, sorted
        by tool — when the policy has exemptions, so a receipt's
        ``policy_digest`` commits to the exact allow-list in force. Omitted
        when there are none, keeping the digest of a policy without exemptions
        identical to what earlier versions computed.
        """
        data: Dict[str, object] = {
            "sources": dict(self._sources),
            "sinks": dict(self._sinks),
            "deny": sorted([list(pair) for pair in self._denied]),
        }
        if self._exemptions:
            data["allow_args"] = [
                self._exemptions[tool].to_dict() for tool in sorted(self._exemptions)
            ]
        return data


class FlowRuleDetector:
    """Blocks a tool call whose sink category is forbidden under active taints.

    Two hooks, because a taint is recorded once its source call has been
    attempted but a sink has to be stopped before it runs:

    * :meth:`check` (pre-execution, in the guard detector loop) trips the brake
      when the call about to run is a sink fed by a denied taint. The taints it
      weighs are the ones already active *plus* the label this very call would
      introduce, so a tool declared as both source and sink — a generic
      ``http_request``, an MCP proxy — is refused on its first call instead of
      egressing once and tainting only afterwards. A denied flow into a sink
      with an :class:`ArgExemption` passes only if that exemption accepts the
      call's arguments; :meth:`allowed_by_policy` then supplies the receipt.
    * :meth:`apply_taint` (post-attempt) records the taint a source call
      introduced, so later sinks see it. It runs whether the call returned or
      raised: nothing proves a read that failed ingested nothing, so a source
      taints the run on attempt, not on success.
    """

    def __init__(self, policy: FlowPolicy):
        self.policy = policy

    def _active_labels(self, run_state: RunState, call: ToolCall) -> Set[str]:
        """Taint labels in force for *this* call, including its own.

        A tool declared as both source and sink — a generic ``http_request``,
        an MCP proxy — would otherwise egress on its first call and only taint
        afterwards, so the content it ingests could never block it. Folding in
        the label the call introduces itself closes that window.
        """
        labels = set(run_state.taint_labels())
        own = self.policy.taint_for(call.name)
        if own is not None:
            labels.add(own)
        return labels

    def _violations(self, run_state: RunState, call: ToolCall) -> List[str]:
        category = self.policy.sink_category_for(call.name)
        if category is None:
            return []  # not a sink — nothing to enforce
        return self.policy.violations(self._active_labels(run_state, call), category)

    def _exemption_verdict(
        self, call: ToolCall
    ) -> Optional[Tuple[bool, Dict[str, object]]]:
        exemption = self.policy.exemption_for(call.name)
        return exemption.evaluate(call.args) if exemption is not None else None

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        if not self._violations(run_state, new_call):
            return None
        verdict = self._exemption_verdict(new_call)
        if verdict is not None and verdict[0]:
            return None  # denied flow, but every recipient is allow-listed
        return InterruptReason.FLOW

    def allowed_by_policy(
        self, run_state: RunState, call: ToolCall
    ) -> Optional[Dict[str, object]]:
        """Receipt payload if a denied flow is let through by an exemption.

        None when the flow is not denied at all (nothing to record) or when it
        is denied and not exempt (:meth:`check` blocks it). Pure function of
        the run's taints and the call, so the guard can ask after every
        detector has passed and mint ``flow_allow`` only for calls that will
        actually run.
        """
        violated = self._violations(run_state, call)
        if not violated:
            return None
        verdict = self._exemption_verdict(call)
        if verdict is None or not verdict[0]:
            return None
        flow = self.explain(run_state, call)
        flow["exemption"] = {"tool": call.name, "allowed": True, **verdict[1]}
        return flow

    def apply_taint(self, run_state: RunState, call: ToolCall) -> Optional[TaintMark]:
        """Record the taint a source call introduced, whatever its outcome.

        Called after the call has been attempted — on the error path too, since
        a read that raised may still have ingested the content it fetched.

        Deduplicated by label: the first call to introduce a label keeps the
        provenance, so the receipt points at where the taint actually entered.
        Returns the new mark, or None if the call is not a source or the label
        is already active.
        """
        label = self.policy.taint_for(call.name)
        if label is None or label in run_state.taint_labels():
            return None
        mark = TaintMark(
            label=label,
            source_tool=call.name,
            call_index=len(run_state.calls) - 1,
        )
        run_state.taints.append(mark)
        return mark

    def explain(self, run_state: RunState, new_call: ToolCall) -> Dict[str, object]:
        """Human- and receipt-readable detail of why a sink call is blocked."""
        category = self.policy.sink_category_for(new_call.name)
        violated = self.policy.violations(
            self._active_labels(run_state, new_call), category or ""
        )
        sources = [
            {"label": t.label, "source_tool": t.source_tool, "call_index": t.call_index}
            for t in run_state.taints
            if t.label in violated
        ]
        own = self.policy.taint_for(new_call.name)
        if own in violated and own not in run_state.taint_labels():
            # Self-tainting sink blocked on its first call: the taint that
            # stops it is the one this very call would introduce, so there is
            # no prior mark to point at. Name the call itself instead, at the
            # index it would have taken had it been allowed to run.
            sources.append(
                {
                    "label": own,
                    "source_tool": new_call.name,
                    "call_index": len(run_state.calls),
                    "self_tainting": True,
                }
            )
        detail: Dict[str, object] = {
            "sink": new_call.name,
            "sink_category": category,
            "violated_taints": violated,
            "tainted_by": sources,
        }
        verdict = self._exemption_verdict(new_call) if violated else None
        if verdict is not None and not verdict[0]:
            # Only when an exemption exists and failed, so a policy without
            # allow_args keeps the exact flow payload earlier versions signed.
            # Names the value that broke it (e.g. bcc=attacker@evil.com) for
            # the operator; the receipt keeps its digest only.
            detail["exemption"] = {"tool": new_call.name, "allowed": False, **verdict[1]}
        return detail


# ---------------------------------------------------------------------------
# Presets — batteries-included policies for the common cases, so the headline
# defence is one readable line instead of three maps.
# ---------------------------------------------------------------------------

def block_exfiltration(
    untrusted_readers: Iterable[str],
    egress_tools: Iterable[str],
    *,
    taint_label: str = "untrusted",
    sink_category: str = "egress",
) -> FlowPolicy:
    """Policy for the canonical prompt-injection -> exfiltration attack.

    Any tool in ``untrusted_readers`` taints the run as ``untrusted``; any tool
    in ``egress_tools`` is an ``egress`` sink; the flow ``untrusted -> egress``
    is denied. So once the agent has read attacker-controlled content, it can no
    longer call a tool that sends data out::

        policy = block_exfiltration(
            untrusted_readers=["read_webpage", "read_email"],
            egress_tools=["send_email", "http_post"],
        )
    """
    return FlowPolicy(
        sources={tool: taint_label for tool in untrusted_readers},
        sinks={tool: sink_category for tool in egress_tools},
        deny=[(taint_label, sink_category)],
    )
