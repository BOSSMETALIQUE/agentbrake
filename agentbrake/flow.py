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
* **Granularity is the tool call.** A single tool that both ingests untrusted
  content *and* egresses in one call is not caught by its own taint (the taint
  is applied only after the call returns). Keep sources and sinks separate.
* **Taint is applied only on success** (``outcome == "ok"``). A read that raises
  ingested nothing, so it introduces no taint.
* **It is not a sandbox.** If the agent reaches a sink through a tool you never
  declared, the flow engine cannot see it. Declare every egress path, and keep
  the allow-list as your hard boundary underneath.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

from .types import InterruptReason, RunState, TaintMark, ToolCall


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


class FlowRuleDetector:
    """Blocks a tool call whose sink category is forbidden under active taints.

    Two hooks, because taint is produced after a source runs but a sink must be
    stopped before it runs:

    * :meth:`check` (pre-execution, in the guard detector loop) trips the brake
      when the call about to run is a sink fed by a denied, currently-active
      taint.
    * :meth:`apply_taint` (post-execution) marks the taint a source call just
      introduced, so later sinks see it.
    """

    def __init__(self, policy: FlowPolicy):
        self.policy = policy

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        category = self.policy.sink_category_for(new_call.name)
        if category is None:
            return None  # not a sink — nothing to enforce
        if self.policy.violations(run_state.taint_labels(), category):
            return InterruptReason.FLOW
        return None

    def apply_taint(self, run_state: RunState, call: ToolCall) -> Optional[TaintMark]:
        """Record the taint a just-executed source call introduced.

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
        violated = self.policy.violations(run_state.taint_labels(), category or "")
        sources = [
            {"label": t.label, "source_tool": t.source_tool, "call_index": t.call_index}
            for t in run_state.taints
            if t.label in violated
        ]
        return {
            "sink": new_call.name,
            "sink_category": category,
            "violated_taints": violated,
            "tainted_by": sources,
        }


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
