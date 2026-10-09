# Design: out-of-band approval for the Claude Code hook

**Status: design only. No code in this document is implemented.**

## The problem

The trifecta rule (v0.4) interrupts the user only on the full lethal trifecta
into an unlisted destination. That is rare by design, so each interrupt
matters. But the interrupt is still shown *in the Claude Code window* as a
permission prompt, and the research (`approval-fatigue-and-trifecta.md`) is
blunt about what happens there: the same person, in the same flow state that
produced the risky action, approves ~97% of prompts, often in seconds. An
approval given in the window that is racing to finish the task is the weakest
possible approval.

The idea here is to route the hook's rare `ask` to a *different channel and a
different moment* — the user's phone, or a Slack message to a second person —
so the decision is made by someone who is not mid-keystroke in the agent. This
reuses the approval machinery AgentBrake already has for its SDK `guard()`
decorator (the FastAPI server, a separate approver secret, signed decision
receipts). It is deliberately not built yet, because the hook's fail-open
timeout (below) makes it a sharp tool.

## What already exists and can be reused

- **`agentbrake.server`**: a FastAPI service with `POST /interrupts` (create a
  pending interrupt), `GET /interrupts/{id}` (an HTML page a human opens),
  `GET /interrupts/{id}/status`, and an approve/decide endpoint gated by a
  **separate approver secret**. Decisions are signed into the same Ed25519
  receipt chain the hook already writes.
- **`AgentBrakeClient`** (`agentbrake/client.py`): holds only the *SDK* secret,
  can `submit_interrupt(...)` and `wait_for_decision(interrupt_id, timeout,
  poll_interval)`, and has **no** approve method by construction. The guarded
  process can raise an interrupt and wait, but cannot approve its own.
- The split — SDK secret creates, approver secret decides — is exactly the
  property we want for out-of-band approval: the machine running Claude Code
  must not be able to approve; a phone or a teammate must.

## Shape of the integration

Add an optional block to `policy.json`:

```json
{
  "remote_approval": {
    "api_url": "https://approve.example.internal",
    "on": ["deny", "ask"],
    "timeout_s": 8,
    "on_timeout": "deny"
  }
}
```

When the trifecta rule reaches a decision in `on`, instead of (or in addition
to) returning the permission decision to Claude Code, the hook would:

1. `submit_interrupt(run_id=session_id, reason="flow", context=<the same
   redacted flow payload it already signs>)` using the SDK secret, getting back
   an `interrupt_id` and a `validation_url`.
2. Push that `validation_url` to the out-of-band channel. Two options:
   - **Phone**: the server already renders an approval page per interrupt; a
     push/SMS/email with the link is a server-side notifier, not hook code.
   - **Slack**: the server posts the link (and the one-or-two-sentence
     message the hook already composes) to a channel or DM, where a second
     person approves it. The approve action calls the approver-secret endpoint.
3. `wait_for_decision(interrupt_id, timeout=remote_approval.timeout_s)` and map
   the result: `approved` → emit `allow` (the call proceeds) and let the
   existing `flow_override` receipt record who approved; `killed` → `deny`.

The hook already mints `flow_ask` locally before it waits, so the chain records
that the flow was caught even if the remote decision never comes.

## The hard limits, stated honestly

- **The hook's own timeout is the ceiling, and it fails *open*.** Claude Code
  kills a PreToolUse hook that exceeds its configured timeout (we ship 10 s)
  and then treats the call as allowed. So the whole out-of-band round trip —
  network to the server, a human noticing the push, tapping approve, the poll
  seeing it — must complete in a handful of seconds, or the call goes through
  unchecked. A phone approval almost never happens that fast. This is the
  single reason the feature is not built: *the enforcement point cannot wait
  for a human who is not already watching.*

  Mitigations, none of them free:
  - Treat timeout as **deny** inside the hook: return `deny` the instant the
    short wait elapses, and surface the pending interrupt so the user can
    approve it and re-run. This turns "slow approval" into "retry", which is
    honest but friction-heavy. It needs the hook to recognise an
    already-approved interrupt on the re-run so the second attempt passes.
  - Raise the Claude Code timeout. It only moves the ceiling; a 60 s hook that
    blocks every risky call for up to a minute is its own kind of pain, and a
    hook killed at 60 s still fails open.
- **A network call on the critical path.** Every guarded call now depends on a
  reachable server. If it is down or slow, you either fail open (no protection)
  or fail closed (every risky call blocked). The local hook has neither
  dependency today.
- **Latency budget.** The local decision is ~0.3–0.4 s (Python start plus
  pydantic/cryptography imports). Adding a submit + poll loop adds at least one
  more round trip before the first poll; `poll_interval` cannot be shorter than
  the server can answer.
- **Trust of the channel.** A Slack message carrying the one-sentence reason
  must not carry the secret or the exact host (the receipt already redacts
  these; the notifier must apply the same redaction). The approver link must be
  unguessable and single-use, which the interrupt id already is, but a channel
  that forwards links widens who can approve.
- **Who approves.** Out-of-band only helps if the approver is *not* the person
  in the flow. A push to the same person's phone, tapped reflexively, rebuilds
  the exact fatigue we are trying to escape. The value is highest with a second
  person (a reviewer, an on-call), which is an organisational choice, not a
  code one.

## What it would take to build it

1. A `remote_approval` policy block with validation (URL, timeout bounded well
   under the hook timeout, `on_timeout` ∈ {deny, allow}).
2. Hook wiring: after a trifecta `ask`/`deny`, submit the interrupt and run a
   bounded `wait_for_decision`; map the result; keep the local `flow_ask` and
   add the `flow_override` on approve. The SDK secret is read from the same
   per-user state directory, never from the project.
3. A server-side notifier (phone/Slack) — this is where most of the work is,
   and it is a server concern, not hook code.
4. Re-run recognition: a decision cache keyed by a digest of the pending call,
   so a user who approves out of band and re-runs the tool is not asked twice.
5. Tests: timeout → `on_timeout`; server unreachable → `on_timeout`; approved
   → `allow` + `flow_override`; killed → `deny`; the SDK secret never leaves
   the state dir; no host or secret value in the interrupt context.

Until the timeout problem has a clean answer (most likely the "timeout = deny,
approve-and-retry" model), the recommendation is to keep enforcement local and
synchronous, and treat out-of-band approval as a reviewer workflow layered on
top of the receipts, not as an inline gate.
