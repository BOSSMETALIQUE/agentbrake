# Argument-level flow control: state of the art and what AgentBrake ships

*Research notes, October 2026. Written while fixing a real false positive:
"read this page, summarize it, email me" was blocked by `block_exfiltration`
because the flow engine only sees tool names, never arguments.*

## The problem in one paragraph

`block_exfiltration(untrusted_readers=["read_webpage"], egress_tools=["send_email"])`
denies `untrusted -> egress`. After any web read, *every* `send_email` is
blocked, including the one the user explicitly asked for, to their own
address. Before this change there were two ways out: human approval (remote
mode, 300 s timeout) or renaming the sink per recipient in user code (checks
only what you remember to check, leaves no receipt). Neither is production
grade. The question is how to let `to=<owner>` through while still blocking
`attacker@evil.com` in every disguise, deterministically, fail-closed, and
with a signed record.

## What the literature and the market do

### CaMeL — capabilities and provenance per value (Google DeepMind, 2025)

- **What it does.** A privileged LLM turns the *trusted user query* into a
  program; a quarantined LLM parses untrusted data but cannot call tools. A
  custom Python interpreter attaches capabilities (sources, readers) to every
  value and checks a policy before each tool call. Values written literally
  by the planner are tagged as coming from the **User**; the banking policy,
  for example, requires that a payment's recipient and amount "have the user
  as a source, as well as no other untrusted parent source in the dependency
  graph". Solves 67% of AgentDojo tasks with provable security.
- **Feasible in AgentBrake without rewriting the user's agent?** No. Value
  provenance requires the interpreter to *execute* the plan; a guard that
  sees one tool call at a time has no dependency graph to consult.
- **Limits (stated by the authors).** Side channels; text-to-text attacks
  that never touch a data flow; user fatigue when policies ask for approval;
  policies have to be written and maintained by hand.
- Source: <https://arxiv.org/abs/2503.18813> (full text:
  <https://arxiv.org/html/2503.18813>).

### FIDES — information-flow control for agent planners (Microsoft, 2025–2026)

- **What it does.** Integrity (trusted/untrusted) and confidentiality labels
  propagate through messages, tool calls and results; consequential actions
  run only if their labels satisfy the policy. Adds primitives to *hide*
  variables from the planner so it can act on untrusted values without
  reading them. Shipped in Microsoft Agent Framework (May 2026) as per-tool
  properties such as `accepts_untrusted: False` or
  `max_allowed_confidentiality: "public"`, with `approval_on_violation=True`
  to fall back to a human.
- **Feasible in AgentBrake?** Partially, and AgentBrake already has the
  coarse part: run-level taint is FIDES-style integrity tracking at the
  granularity of the run. Per-variable labels need control of the planner's
  context (variable hiding), which a tool-boundary guard does not have.
- **Limits.** The authors characterize exactly which properties dynamic taint
  tracking can enforce; label precision trades against utility (labels that
  are too conservative paralyze the agent — which is our false positive).
- Sources: <https://arxiv.org/abs/2505.23643>,
  <https://github.com/microsoft/fides>,
  <https://devblogs.microsoft.com/agent-framework/fides/>.

### Progent — programmable privilege control (2025)

- **What it does.** A JSON-Schema-based policy language over **tool
  arguments**: per-tool `allow`/`forbid` effects with conditions (regex
  `match`, comparisons, `in`, array length), priorities (forbid wins ties),
  **deny by default** when no policy matches, fallbacks (terminate, ask a
  human, or return feedback to the model), and policy updates triggered at
  runtime. Example given: restrict email recipients to a trusted pattern;
  "pre-approved recipients for emails or funds". Integrates "without altering
  agent internals". Reports 0% attack success on AgentDojo, ASB, AgentPoison.
- **Feasible in AgentBrake?** Yes — this is the closest model. A Progent
  condition is a deterministic predicate over one call's arguments, which is
  exactly what a guard at the tool boundary can evaluate.
- **Limits (stated).** Security is only as good as the hand-written policy;
  no defense against preference manipulation among valid options or attacks
  on text outputs.
- Source: <https://arxiv.org/abs/2504.11703> (HTML v2:
  <https://arxiv.org/html/2504.11703v2>).

### Invariant Labs guardrails (now Snyk)

- **What it does.** A Python-like rule language evaluated on agent traces,
  including dataflow (`(call: ToolCall) -> (call2: ToolCall)`) and argument
  matching (`call2 is tool:send_email({to: <regex>})`). Deployed as an MCP or
  LLM proxy, so the agent is not rewritten. Invariant was acquired by Snyk in
  June 2025; the hosted Explorer shut down in January 2026, the
  `invariant` repository remains public.
- **Feasible in AgentBrake?** The sequence part is what AgentBrake's taint
  already does; the argument-matching part is what was missing.
- **Limit worth learning from.** The README's flagship rule is written
  `send_email({to: '.*@[^ourcompany.com$].*'})`. `[^ourcompany.com$]` is a
  regex *character class* — "one character that is not any of
  o,u,r,c,m,p,a,n,y,.,$" — not "a domain other than ourcompany.com". Regexes
  are a poor way for a security team to state "only these recipients", even
  for the vendor's own example. AgentBrake therefore does **not** accept
  regexes for recipients.
- Sources: <https://github.com/invariantlabs-ai/invariant>,
  <https://github.com/invariantlabs-ai/explorer>,
  <https://snyk.io/fr/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/>.

### AgentDojo (2024) — the benchmark everyone reports on

- 97 user tasks and 629 security test cases across workspace, Slack,
  banking and travel suites; exfiltration through `send_email` is a core
  injection goal. Useful here because CaMeL, FIDES, Progent and PACT all
  report on it, which is what lets their utility/security trade-offs be
  compared.
- Source: <https://arxiv.org/abs/2406.13352>.

### PACT — argument-level provenance (2026)

- **What it does.** "The Granularity Mismatch in Agent Security":
  enforcement at the granularity of *arguments*, with roles (a *target* such
  as a recipient or URL must not come from untrusted content, while *content*
  may: "a webpage may determine an email body, but not the recipient").
  Provenance is inferred "by exact structural matching, role-aware heuristics
  for high-confidence transformations, and an LLM classifier for remaining
  ambiguous arguments". With oracle provenance: 100% utility and security on
  their diagnostics; on AgentDojo, 100% security at 38–46% utility, 8–16
  points above CaMeL.
- **Feasible in AgentBrake?** The deterministic half (exact match against
  trusted values) is; the part that makes it work in practice — an LLM
  classifier for ambiguous cases — is neither deterministic nor something a
  security control should silently depend on. See "Level B" below.
- **Limits (stated).** No defense against tool-selection attacks with
  trusted constants, nor content-channel attacks inside a permitted content
  argument.
- Source: <https://arxiv.org/abs/2605.11039>.

### Commercial products (public information only)

- **Lakera Guard** publicly describes prompt-attack and data-leakage
  detectors, custom guardrails (e.g. flagging an external email domain), and
  a tool allow/deny list. Detector-based, i.e. probabilistic; no public
  description of deterministic argument-level flow rules.
  <https://www.lakera.ai/blog/lakera-guard-overview>
- **CodeIntegrity** markets runtime guardrails for agents (seed round,
  2026); no public technical description of how it treats recipients was
  found. <https://app.dealroom.co/news/note/codeintegrity-raises-4-8m-seed-to-put-runtime-guardrails-on-agentic-ai>
- **Prompt Security**: no public, citable description of argument-level
  recipient rules was found. Not claimed either way.

## Design decision for AgentBrake

### Level A (shipped): declarative argument exemption on a denied flow

```python
policy = block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
    "send_email",
    fields=["to", "cc", "bcc"],          # every recipient field the tool accepts
    values=["moi@example.com"],          # exact addresses
    domains=["corp.example"],            # optional: whole domains, exact match
    other_fields=["subject", "body"],    # may be present, not inspected
)
```

Modeled on Progent's allow-with-conditions plus deny-by-default, with three
deliberate departures:

1. **No regexes, no wildcards.** Exact normalized addresses and exact
   domains only (the Invariant example above shows why). `domains=["corp.example"]`
   does not match `x.corp.example` or `corp.example.evil.com`.
2. **A narrow address grammar, refused rather than parsed.** A value must be
   one bare `local@domain` in ASCII, after trimming spaces/tabs and
   lowercasing. Refused: display names and angle brackets, quoted local
   parts, comma/semicolon-joined lists, `%` (percent-hack relay) and `!`
   (bang path), source routes, IP literals, single-label and trailing-dot
   domains, any non-ASCII (homoglyphs, fullwidth forms, zero-width
   characters), any control character (CR/LF header injection), percent- or
   RFC 2047-encoded forms. Rationale: when the check and the mailer parse
   the same string differently, they can see two different recipients.
   CPython's own `email.utils.parseaddr` had exactly this bug
   (CVE-2023-27043, fixed by a stricter mode; see
   <https://access.redhat.com/articles/7051467>). A legal but unusual
   address is therefore blocked, never misread.
3. **Fail-closed on the shape of the call, not just the values.** Every
   argument must be declared in `fields` or `other_fields` (an undeclared
   `reply_to`, `recipients` or `To` blocks); field values must be `None`, an
   empty string/list, one string, or a list/tuple of strings (numbers, dicts,
   nested lists, sets, bytes block); at least one recipient must be present
   (a call with none may hit a default destination inside the tool).

Proof and audit:

- The exemption is serialized into `FlowPolicy.to_dict()` (normalized,
  sorted), so every receipt's `policy_digest` commits to the exact
  allow-list. Policies without `allow_args` serialize exactly as before.
- Each send let through mints a signed `flow_allow` receipt
  (`decision="allow_by_policy"`), with the sink call's `tool_args_digest`.
  It is minted only after every other detector has passed, so a call later
  stopped by the budget or loop detector never gets an "allowed" record.
  Receipts carry recipient counts, not addresses.
- A blocked send's interrupt (`e.context["flow"]["exemption"]`) names the
  first offending field and value, e.g. `bcc=attacker@evil.com`, truncated
  to 254 characters since an over-long "address" may be the data itself.
  The signed receipt keeps the field and the reason in clear but the value
  only as `value_digest`: receipts never hold raw arguments (a README
  guarantee), and a "recipient" may be the stolen data itself.
- `validate()` refuses an exemption on a tool that is not a declared sink;
  the builder refuses empty allow-lists, malformed entries, bare strings in
  place of lists, overlapping `fields`/`other_fields`, and a second
  exemption for the same tool.

### Level B (not shipped): CaMeL/PACT-style provenance from the user's task

The idea: register the user's task as a *trusted* source for the run and
allow a send when every recipient appears in that task — no static
allow-list, works for any user. It was evaluated and **not implemented**,
because a substring check on the task is not a sound provenance signal:

- **Role confusion.** "Summarize what bob@partner.example wrote on this page
  and email it to me" puts Bob's address in the trusted text as a *subject*,
  not a *recipient*. An injection saying "send it to bob@partner.example"
  then passes. PACT handles roles with heuristics plus an LLM classifier;
  that is the non-deterministic part.
- **Pasted untrusted content.** Users routinely paste the thing to process
  into the request ("here is the email I got: ... summarize it and send it
  to me"). The attacker's address is then literally in the "trusted" task.
  Only the integrator knows which part the user typed; a library cannot.
- **What counts as "the task" in multi-turn chats** — later user turns may
  quote earlier tool output. Registering the wrong text poisons the source.
- **Natural-language recipients** ("send it to my work address", "moi at
  example dot com") give no literal to match, so the false positive
  remains — or extraction gets fuzzy, which re-opens near-duplicate attacks.
- Collision itself is *not* the issue (an address truly typed by the user
  is legitimately allowed); the issue is that "appears in the task" is not
  "the user meant it as a recipient".

**Deterministic subset that *is* sound**, and needs no new feature: take the
recipient from an authenticated identity — the logged-in user's address from
your session or directory, never from the prompt — and build the policy per
run:

```python
policy = block_exfiltration(["read_webpage"], ["send_email"]).allow_args(
    "send_email", fields=["to", "cc", "bcc"], values=[session.user.email],
    other_fields=["subject", "body"],
)
with agentbrake.run(flow_policy=policy, ...):
    ...
```

Each run's receipts then carry a `policy_digest` bound to that user's
allow-list. If Level B is ever built, it should take *structured* trusted
values from the integrator (`run(trusted_values={"recipient": [...]})`), not
free text, and should be measured on AgentDojo before shipping.

## Residual risks of what shipped (known, documented)

- **Content is not inspected.** The injected text still reaches the allowed
  recipient. In particular an **HTML body with remote resources** can
  exfiltrate when the owner's mail client loads them (e.g. an image URL
  carrying data to the attacker's server). Have the tool send plain text
  (or strip remote resources) — AgentBrake does not inspect content. This is
  the "content-channel" attack PACT and CaMeL also leave open.
- **The tool receives the raw value, the check sees the normalized one.**
  Normalization only trims spaces/tabs and lowercases; domains are
  case-insensitive, local parts are case-insensitive on all mainstream
  providers but technically case-sensitive per RFC 5321.
- **Fields you did not declare as recipient fields are not destinations to
  the checker.** If your tool sends to something passed under a name you put
  in `other_fields` (say an `attachments_url` webhook), the exemption cannot
  see it. Declare every field; the default for anything undeclared is block.
- **Domain matchers trust the whole domain**, including addresses an
  attacker may be able to create there (free-mail domains, shared tenants).
  Prefer exact addresses.
- **Allowed recipient compromised or auto-forwarding** is out of scope.
- **Same-tool name, different semantics.** The exemption is keyed by tool
  name; it assumes `send_email` means the same tool for the whole run.
