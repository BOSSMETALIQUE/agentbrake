# Changelog

All notable changes to AgentBrake are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.5] - 2026-10-11

Fixes a retry storm that the default configuration let run unchecked. No receipt format change,
`verify_chain` unchanged, no API change.

### Behaviour changes
- **The pagination exemption of `RetryStormDetector` now needs successes.** With `progress_aware=True`
  (the default), a same-tool burst whose numeric argument climbs or drops on every call is exempt only
  while the finished calls in the window are not failure-dominated: no error, or strictly more
  successes than errors. Before, the arguments alone decided. A run that retries a failing tool with
  `page=1, 2, 3 ...` is now stopped with `InterruptReason.LOOP` at the fifth same-tool call (defaults:
  5 calls in a window of 10). A real page walk with an isolated failure is still let through; calls
  still pending are counted neither way. `progress_aware=False` is unchanged.

### Fixed
- **Retry storms disguised as pagination were never stopped.** `page=1, 2, 3 ...` against a tool that
  always fails passed the progress check on every turn, so neither `LoopDetector` (new arguments,
  new hash) nor `RetryStormDetector` (exempted as pagination) fired. Measured on Claude Haiku 4.5:
  30 turns and about 563,000 input tokens per run with AgentBrake on, the same as without it. See
  `docs/research/cost-measurement.md`.
- **Docstrings of `LoopDetector` and `RetryStormDetector`** pointed varied-argument loops to
  `RetryStormDetector` without mentioning the pagination exemption. They now state it, its success
  condition, and that the window is a call count, not a time span.

## [0.3.4] - 2026-10-10

Polish release from a field test on a real Claude agent. No receipt format change, `verify_chain`
unchanged, existing budgets trip at the same call. Backward compatible except for the input validation
listed under "Behaviour changes".

### Behaviour changes
- **Invalid USD amounts raise instead of being coerced.** `budget_usd` (`init()`, `run()`, `Run`,
  `BudgetDetector`) and `cost_usd` / `total_cost_usd` (`ToolCall`, `RunState`) reject `bool`,
  non-numbers, NaN and negative amounts with `TypeError` / `ValueError`. Before, a cost of any type
  other than `float` silently became `0.0`, and a NaN budget never tripped.
- **An infinite budget is rejected.** `budget_usd=float("inf")` (or `math.inf`, `Decimal("Infinity")`)
  raises `ValueError: budget_usd must be a finite amount, got inf. For no spending limit, pass
  budget_usd=agentbrake.UNLIMITED`. Use `agentbrake.UNLIMITED` for an unlimited run.
- **The validation page no longer parses numeric strings as costs.** A `total_cost_usd` sent as a
  string (e.g. `"1.5"`), a bool, NaN, inf or a negative number is displayed as "invalid" instead of
  being converted ("$1.50", "$1.00" for `true`, "$nan", "$0.00"). The SDK always sends a number;
  this only affects hand-crafted POSTs to `/interrupts`. A missing or `null` cost still shows "$0.00".

### Fixed
- **Budget bypass with integer costs.** `ToolCall(cost_usd=1)` and `RunState(total_cost_usd=2)` silently
  became `0.0`: the convenience kwargs were converted only when they were a `float`, and any other type
  was dropped, so a provider wrapper reporting whole dollars never moved the budget. `cost_usd` /
  `total_cost_usd` (constructor kwargs and property setters) now accept `int`, `float`, `Decimal` and
  other real numbers. `bool`, non-numbers, NaN, ±inf and negative amounts raise `TypeError` /
  `ValueError` naming the field, as do negative `*_micro` values and passing both `cost_usd` and
  `cost_usd_micro`. `BudgetDetector` (so `run()` / `init()`) validates `budget_usd` the same way: a NaN
  budget never tripped. The validation page shows "invalid" for a bool / NaN / inf / negative /
  non-numeric `total_cost_usd` instead of "$1.00", "$nan" or "$0.00". New helpers
  `types.check_usd()` / `types.usd_to_micro()`. See "Behaviour changes" for what now raises.
- **Ephemeral signing key no longer goes unnoticed.** A run given `receipts_path` while neither
  `AGENTBRAKE_SIGNING_KEY_FILE` nor `AGENTBRAKE_SIGNING_SEED` is set now emits
  `signing.EphemeralSigningKeyWarning`, naming the file, the throwaway `key_id` and the exact
  `agentbrake keygen` + env commands. The suggested key path is built from the real home directory
  (`Path.home()`) and quoted, e.g. `agentbrake keygen -o "C:\Users\me\.agentbrake\signing_key.pem"`,
  since `~` is not expanded by Windows cmd (or inside an environment variable). Previously the receipts were written silently and could never be
  verified (`export` showed "UNSIGNED", `verify` failed with "no public key known"). No key is created
  on your behalf: an unencrypted private key appearing on disk unasked is a risk you should choose, and
  swapping the signer mid-process would orphan what it already signed. New `attest.signer_is_ephemeral()`.
  `verify` adds a hint when it hits an unknown key; `export` explains what an unsigned head means.
- **Loop detector no longer stops a normal retry.** The `LoopDetector` threshold was hard-wired to 3, so
  a tool that failed twice was interrupted as a "loop" on its next retry. It is now configurable via
  `run()` / `init()` / `Run(loop_threshold=...)` and defaults to `DEFAULT_LOOP_THRESHOLD = 4`: a try
  plus two retries run, the 4th identical consecutive call is blocked (still one call before the
  same-tool retry-storm detector). `loop_threshold=3` restores the old behavior.
- **`agentbrake verify` no longer claims guarantees on failure.** "What this verification PROVES" is
  printed only when every check passes; a failing run lists each failed check and states that nothing is
  proven. Same for `verify-receipt`.
- **Raw ledger passed to `verify`.** `agentbrake verify receipts.jsonl` (also `verify-receipt`,
  `report`) now says it is a raw ledger and names the command to run first (`agentbrake export
  --receipts ...`), exit code 2, instead of a parse error or a misleading
  "entries: 0 ... VERIFICATION FAILED".
- **`str(AgentBrakeInterrupt)` is one line**: `AgentBrake interrupt: <reason> on tool '<tool>'
  (run_id=<id>)`. It used to embed the whole run state (args, history, receipt signature), flooding logs
  and the model's context when returned as a tool result. Detail is unchanged on `e.reason` /
  `e.context`, plus new read-only `e.tool`, `e.run_id`, `e.receipt`. The exception now also survives
  pickling. A budget block caused by a `0.0` budget (the default, e.g. `init()` without `budget_usd`)
  says so on the same line: `...: budget_usd is 0.0 (the default); set budget_usd=<amount> or
  budget_usd=agentbrake.UNLIMITED`. Budget interrupts carry `e.context["budget_usd"]`.
- **The flat $0.01 per tool call is labeled an estimate.** `ToolCall.cost_estimated` marks it,
  `RunState.cost_is_estimate` reports it, interrupt contexts carry `cost_is_estimate` and new detector
  receipts `total_cost_is_estimate`; the validation page shows "Estimated cost" (contexts from older
  SDKs keep "Total cost"). Public constant `ESTIMATED_COST_PER_TOOL_CALL_USD`. Amounts and `budget_usd`
  semantics are unchanged.

- **README no longer overclaims.** Receipts are no longer said to cover "every enforcement decision"
  (a remote-mode timeout mints none; a retry storm is recorded as `loop`), offline third-party
  verification is stated to require a persistent signing key, and the tagline, "stable" status, asyncio
  isolation (untested), CometAPI model count and OWASP ASI02 coverage are reworded to what is tested or
  sourced. The opening incidents are labeled illustrative.

### Added
- `agentbrake --version`.
- **`agentbrake.UNLIMITED`**: pass `budget_usd=agentbrake.UNLIMITED` for no spending limit. There was
  no way to say so before (the default `0.0` blocks the first guarded call, `None` in `run()` means
  "inherit from `init()`"). In `run()` it overrides an inherited budget. The error raised for an
  infinite budget names it.

## [0.3.3] - 2026-10-09

### Added
- **Argument-level flow exemptions** — `FlowPolicy.allow_args(tool, fields=..., values=..., domains=...,
  other_fields=...)`. Fixes the false positive where "read this page and email me a summary" was
  blocked by `block_exfiltration`: after an untrusted read, a send now passes only if every recipient
  in every declared field is an allow-listed address (or on an allow-listed domain, exact match).
  Deterministic and fail-closed: an undeclared argument, a value that is not a string or list of
  strings, a call with no recipient, or anything that is not one plain ASCII `local@domain` (display
  names, comma-joined lists, `%`/`!` relays, quoted local parts, homoglyphs, CR/LF) blocks. No regexes.
  `validate()` rejects an exemption on a tool that is not a declared sink; the builder rejects empty
  allow-lists, malformed entries, bare strings where a list is expected, overlapping fields, and a
  second exemption for the same tool. Without `allow_args`, behavior and `policy_digest` are
  unchanged.
- **`flow_allow` receipts** (`decision="allow_by_policy"`): every send let through by an exemption is
  signed into the same hash chain as blocks, with the call's `tool_args_digest`; the exemption is
  serialized into `FlowPolicy.to_dict()`, so `policy_digest` commits to the exact allow-list. Minted
  only once every detector has passed. The compliance report counts them separately
  (`summary.flow_allows`) instead of as human decisions.
- A blocked send's interrupt names the value that broke the exemption
  (`e.context["flow"]["exemption"]`: `field`, `value`, `value_digest`, `reason`); the signed receipt
  keeps the digest, never the raw value (`receipts.flow_for_receipt`).
- `examples/09_allow_owner_email.py`: the owner gets the summary, `attacker@evil.com` and a hidden
  `bcc` are blocked, three receipts verify. Covered by `tests/test_flow_allow_args.py`.
- Research notes: `docs/research/argument-level-flow.md` (CaMeL, FIDES, Progent, Invariant, PACT;
  why prompt-derived provenance was evaluated and not shipped).

## [0.3.2] - 2026-10-04

Documentation and examples only — no change to package behavior.

### Added
- **LangGraph flow-control example** (`examples/08_langgraph_flow_middleware.py`): AgentBrake wired
  into a real LangGraph agent through LangChain v1's `wrap_tool_call` middleware hook, blocking the
  prompt-injection → exfiltration flow and minting a verifiable receipt. Runs with no API key and no
  network: the model is a scripted stand-in, the "poisoned page" a local string. A second part
  demonstrates how `ToolNode(handle_tool_errors=True)` silently demotes an exception-based breaker to
  advisory. Covered by `tests/test_langgraph_middleware.py` in two tiers — the policy tests run
  everywhere, the integration tests skip without `langchain`/`langgraph` installed.
- **Research notes** (`docs/research/framework-security-map.md`): a cited survey of how LangGraph,
  CrewAI, AutoGen, AG2, the OpenAI Agents SDK and Pydantic AI handle untrusted-input → egress flows.
  None of them ships native taint tracking in the versions reviewed, and all pass MCP tool
  descriptions to the model without an integrity check. Includes the per-framework hook AgentBrake
  attaches to, and a draft write-up (`docs/research/writeup-draft.md`).

### Fixed
- README cited the EU AI Act high-risk obligations as enforceable from 2 August 2026 with penalties
  up to 7% of global turnover. The Digital Omnibus (Regulation (EU) 2026/1744) deferred them to
  2 December 2027 (Annex III standalone systems) and 2 August 2028 (Annex I AI embedded in regulated
  products); the 7% ceiling applies to prohibited practices, not to high-risk obligations. Both the
  banner and the "Why this matters now" section now state the current dates and carry no penalty
  figure.
- README and example documentation described flow-control taint as applied only on a successful
  source call. Taint is applied on *attempt* — a source that raises taints the run too, since nothing
  proves a failed read ingested nothing. The stated limitations now match the engine, including that
  a tool declared as both source and sink is refused on its first call.
- `FileKeyStore` docstring claimed it auto-generates a key when the file is absent;
  `load_private_key()` raises `FileNotFoundError`. Docstring corrected — no behavior change.
- A type annotation on a local dict in `agentbrake/__init__.py` so `mypy agentbrake` passes in CI.
  No runtime effect.

## [0.3.1] - 2026-09-23

### Added
- **Signed receipts for detector blocks** (`mint_detector_receipt`,
  `build_detector_attestation`): a loop, budget or escalation block now mints a signed, hash-chained
  receipt into the same ledger and the same format as a flow block, so an autonomous stop is as
  provable as a human decision. The attestation carries `decision: "block"`, the detector `kind`, the
  tool, and a context summary (cumulative cost, call count, plus the budget ceiling or the last five
  call names). Two limits worth knowing: a **retry-storm block is recorded with kind `loop`**, because
  `RetryStormDetector` reports `InterruptReason.LOOP` — it cannot be told apart from an exact loop in
  the receipt; and a **remote-mode decision timeout mints no receipt**, since `TIMEOUT` is raised
  before the minting step is reached.
- **`policy_digest` on flow receipts**: `flow_block` and `flow_override` attestations carry a sha256
  digest of the policy that was in force, so an auditor can tell not just that a call was blocked but
  under which rules. Detector and delegation receipts accept the field but are not passed one, so in
  practice only flow receipts carry it.
- **Flow override receipts** (`mint_flow_override_receipt`): a human who *approves* a flow the engine
  had blocked is recorded in the same chain, with the interrupt id that authorised it. A ledger that
  only ever proves "we stopped this" would leave the most audit-worthy event — an exfiltration waved
  through — as the one thing with no trace.
- **`KeyStore` abstraction** for Ed25519 signing keys: a `KeyStore` protocol with `InMemoryKeyStore`
  and `FileKeyStore` (unencrypted PKCS#8 PEM) implementations, leaving room for hardware-backed
  storage later. Not yet wired into the signing path — `resolve_signer_from_env()` still builds
  signers directly from `AGENTBRAKE_SIGNING_KEY_FILE` / `_SEED` / the legacy HMAC secret.
- **`FlowPolicy.validate()`**: raises on a deny rule that can never fire (a typo'd taint label or sink
  category), called automatically when a policy is attached to a run. For a security control a silent
  no-op is the worst failure mode, because it is indistinguishable from working.
  **`FlowPolicy.undeclared_tools()`** warns about allow-listed tools the policy declares neither
  source nor sink — every one is a path the flow engine cannot see.
- arXiv research survey on agent security hardening (`docs/research/arxiv-survey.md`).

### Changed
- **Cost is accumulated in integer micro-dollars.** `ToolCall.cost_usd_micro` and
  `RunState.total_cost_usd_micro` hold integers, so the repeated float addition that used to
  accumulate spend can no longer drift. `cost_usd` / `total_cost_usd` remain as float property views
  (with setters), and a float `cost_usd=` keyword is still accepted and converted, so existing code
  keeps working. Note the ceiling *comparison* in `BudgetDetector.check` is still performed in
  floats — the integer accounting removes cumulative drift, not the final float compare.

### Fixed
- **Two taint-tracking bypasses in the flow engine.** Taint is now applied on *attempt* rather than on
  success: a source tool that fetched attacker-controlled content and then raised has still ingested
  it, and an agent loop will hand the exception text — which can carry that content — back to the
  model, so nothing proves a failed read was harmless. And a tool declared as *both* source and sink
  (a generic `http_request`, an MCP proxy) is now checked against the taint it would introduce itself,
  so it is refused on its first call instead of egressing once and tainting only afterwards.
- **Approvals are bound to the action they approve.** The interrupt context now carries a
  `pending_call` with the tool, its arguments, and an `args_digest`; the approver echoes the digest
  back and the server rejects a decision whose digest does not match the pending call. Previously an
  approver saw only a tool *name* — approving `send_email` without sight of `to=attacker@evil.com` —
  because the pending call is appended to the run state only after the detectors pass.

## [0.3.0] - 2026-09-08

### Added
- **CometAPI provider** (`agentbrake.providers.cometapi`, `pip install py-agentbrake[cometapi]`): real
  token-based LLM cost tracking through CometAPI's OpenAI-compatible gateway to 500+ models.
  `complete()` makes a priced call and records it in one step; `track()`/`record()` let you price a
  call you made yourself. Spend is wired into the active run's `BudgetDetector`, so real usage — not
  the flat per-call estimate — can trip the budget interrupt.
- `py.typed` marker (PEP 561) — the package ships inline type hints; downstream mypy/pyright now
  picks them up instead of treating the package as untyped.
- `CHANGELOG.md` (this file) and `SECURITY.md`.
- `ruff` and `mypy` wired into CI as a dedicated `lint` job.
- Test coverage measured in CI (`pytest --cov`).
- `twine check --strict` wired into CI against the built sdist/wheel, so a packaging-metadata
  regression (like the missing classifiers below) fails CI instead of shipping unnoticed.

### Fixed
- `pyproject.toml` had no `classifiers`, `project.urls`, `authors`, or a structured `license` field —
  confirmed empty in the published PyPI metadata. All four are now populated (SPDX `license = "MIT"`,
  GitHub + docs links, keywords mirroring the GitHub topics).
- The package version was hand-duplicated in both `pyproject.toml` and `agentbrake/__init__.py` and
  had already drifted out of sync once (see `53bfa12`). `pyproject.toml` now reads the version
  dynamically from `agentbrake.__version__` — one source of truth.
- A handful of real `mypy`/`ruff` findings surfaced by turning static analysis on for the first time:
  an unreachable-at-runtime but statically-undefined `datetime` reference in `cli.py`, an
  `Optional[Signer]` mistyped as `Signer`, a `Run.__exit__` return type that could imply exception
  suppression it never does, and a couple of unused imports.

### Changed
- README documents the single-process assumption behind the remote-mode receipt chain lock: running
  multiple `uvicorn` workers/replicas against the same `agentbrake.db` is not supported.

## [0.2.4] - 2026-08-16
### Added
- Narrated demo runner for the verifiable-audit-trail example.
### Changed
- Documentation sync: delegation section, status/roadmap, OWASP Top 10 for Agentic Applications mapping.

## [0.2.3] - 2026-08-14
### Fixed
- README cleanup after a bad merge.

## [0.2.2] - 2026-08-14
### Fixed
- Removed a stray build script and cleaned up the PyPI project description.

## [0.2.0] - 2026-08-14
### Added
- `RetryStormDetector` and `cost_from_tokens()` — catches a tool hammered across changing args or
  interleaved calls, not just exact repeats; progress-aware so real pagination passes.
- Taint-tracking flow engine (`FlowPolicy`, `FlowRuleDetector`, `block_exfiltration()`) — stops the
  prompt-injection → exfiltration attack an allow-list alone cannot see (OWASP ASI01).
- Signed, hash-chained receipts for autonomous flow blocks, sharing the same ledger, signer, and
  `agentbrake verify` CLI as human decisions.
- Third-party verifiable receipts: Ed25519 signatures, standalone `agentbrake verify` CLI — an
  auditor verifies offline with only the public key, no trust in the server required.
- RFC 6962 Merkle log: signed chain head, cross-export consistency checks, single-receipt inclusion
  proofs (`agentbrake prove` / `agentbrake verify-receipt`).
- Signed delegation tokens (`agentbrake.delegation`) — bind delegator, delegatee, a digest of the
  original user intent, a narrowing tool subset, and a TTL across agent hops (OWASP ASI03).
- Compliance report generation (`agentbrake report`) — auditor-readable Markdown from a verified
  export bundle.
- Progress-aware loop detection — a monotonic numeric argument (pagination) no longer false-positives
  as a stuck loop.

## [0.1.2] - 2026-06-29
### Fixed
- README now renders correctly on the PyPI project page.

## [0.1.0] - 2026-06-29
### Added
- Initial public release: `agentbrake.init()` / `run()` / `guard()`, with `LoopDetector`,
  `BudgetDetector`, and `EscalationDetector` active out of the box.
- Remote mode: FastAPI backend with a human-in-the-loop validation UI, SDK/approver secret split so
  the guarded agent process cannot approve its own interruption.
- Signed, hash-chained attestations for human approve/kill decisions.

[Unreleased]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.5...HEAD
[0.3.5]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.0...v0.2.2
[0.2.0]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/BOSSMETALIQUE/agentbrake/releases/tag/v0.1.0
