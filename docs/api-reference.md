# API reference

An index of AgentBrake's public API, one line per symbol. This is a lookup
table, not a tutorial — for the "why" behind each piece, follow the links
into the main [README](../README.md). Anything not listed here (names
starting with `_`, and everything under `agentbrake.server`, which is the
backend process, not something you import) is internal and may change
without notice.

## `agentbrake` (top level)

| Symbol | What it is |
|---|---|
| `init(...)` | Configure the process-wide default run. See [Quick start](../README.md#quick-start). |
| `run(...)` | Open an isolated `Run` as a context manager; unset args inherit from `init()`. See [Quick start](../README.md#quick-start). |
| `guard()` | Decorator that wraps a tool-dispatch function with the circuit breaker. See [Quick start](../README.md#quick-start). |
| `current_run()` | The active `Run` — innermost `with run(...)`, else the `init()` default, else `None`. |
| `Run` | One guarded run: config, detectors, and a fresh `RunState`. Returned by `run()`. |
| `AgentBrakeInterrupt` | Exception raised when a detector trips. Carries `.reason` and `.context`. |
| `InterruptReason` | Enum: `LOOP`, `BUDGET`, `ESCALATION`, `TIMEOUT`, `FLOW`, `DELEGATION`. |
| `RunState` | Per-run state: id, cost, call history, active taints. |
| `ToolCall` | One recorded tool call: name, args, cost, outcome. |
| `LoopDetector`, `RetryStormDetector`, `BudgetDetector`, `EscalationDetector` | The four always-on detectors. See [What it detects](../README.md#what-it-detects). |
| `cost_from_tokens(model, input_tokens, output_tokens)` | Estimate USD cost from token usage using the built-in `PRICING` table. |
| `FlowPolicy`, `FlowRuleDetector`, `block_exfiltration(...)` | Taint-tracking flow control. See [Flow control](../README.md#flow-control-taint-tracking). |
| `delegation` | The `agentbrake.delegation` module, re-exported. See [Delegation](../README.md#delegation-inter-agent-trust). |
| `DelegationError` | Raised when a delegation token fails to verify. |
| `receipts` | The `agentbrake.receipts` module, re-exported. See [Verifiable receipts](../README.md#verifiable-receipts). |
| `signing` | The `agentbrake.signing` module, re-exported. |
| `__version__` | Current package version string. |

## `agentbrake.detectors`

| Symbol | What it is |
|---|---|
| `LoopDetector` | Flags when N consecutive calls share the same structural hash. |
| `RetryStormDetector` | Flags when the same tool is hammered too many times in a recent window, even with changing args. |
| `BudgetDetector` | Flags when projected total cost would exceed the configured budget. |
| `EscalationDetector` | Flags when a tool call targets a name outside the allow-list. |
| `cost_from_tokens(model, input_tokens, output_tokens)` | See above. |
| `PRICING`, `DEFAULT_PRICING` | The per-model USD-per-million-token table backing `cost_from_tokens`, and its fallback for unknown models. |

## `agentbrake.flow`

| Symbol | What it is |
|---|---|
| `FlowPolicy` | Declares taint sources, sinks, and denied `(taint, sink category)` pairs. Buildable fluently via `.source()` / `.sink()` / `.deny_flow()`. |
| `FlowRuleDetector` | The detector that enforces a `FlowPolicy` against a run's active taints. |
| `block_exfiltration(untrusted_readers, egress_tools)` | Convenience constructor for the canonical prompt-injection → exfiltration policy. |

## `agentbrake.delegation`

| Symbol | What it is |
|---|---|
| `grant(...)` | Issue a signed `DelegationToken`, optionally narrowing a `parent` token. |
| `DelegationToken` | A delegation chain: one or more signed links, root grant first. |
| `verify(token, ...)` | Deep-verify a token's signatures, contiguity, scope-narrowing, and shared intent digest. |
| `accept(token, ...)` | Verify a token and wrap it as an `AcceptedDelegation` ready to hand to `run(delegation=...)`. |
| `AcceptedDelegation` | A token that passed `accept()`. |
| `DelegationDetector` | Blocks tool calls outside the delegated scope, or after expiry. |
| `intent_digest_for(intent)` | `sha256:<hex>` digest of the raw intent text — the value frozen across a delegation chain. |
| `token_receipt_payload(token)` | The receipt payload for a token: signed links plus derived facts. |
| `record_event(...)` | Mint a signed delegation-lifecycle receipt (`accept` / `reject` / `block`) into a ledger. |
| `DelegationError` | Raised on any verification failure. |

See [Delegation limitations](../README.md#limitations-read-these-1) for what a token does and does not prove.

## `agentbrake.receipts`

| Symbol | What it is |
|---|---|
| `Ledger` | Protocol for an append-only store of chained receipt rows. |
| `InMemoryLedger` | Per-run, in-process chain; lost when the process exits (the `run()` default). |
| `JsonlLedger` | File-backed chain, one JSON object per line, for durable receipts (`run(receipts_path=...)`). |
| `mint_flow_receipt(...)` | Build, sign, and append a flow-block attestation. |
| `mint_delegation_receipt(...)` | Build, sign, and append a delegation-event attestation. |
| `build_flow_attestation(...)`, `build_delegation_attestation(...)` | Lower-level attestation builders behind the `mint_*` helpers. |
| `sink_call_digest(call)` | Digest binding a receipt to the blocked call, without exposing raw args. |
| `receipt_summary(row)` | The small, proof-bearing slice of a receipt to attach to an `AgentBrakeInterrupt`. |
| `verify_chain(rows, ...)` | Verify a ledger's signatures and hash-chain links. Returns `(ok, error_message)`. |

## `agentbrake.signing`

| Symbol | What it is |
|---|---|
| `Signer` | Protocol for anything that can sign attestation bytes and identify its key. |
| `Ed25519Signer` | Signs with an Ed25519 private key; verifiable with only the public key — the third-party-verifiable default. |
| `Ed25519Verifier` | Public-key-only verification — what a third party runs. |
| `verify_ed25519(public_key_hex, message, signature_hex)` | One-shot Ed25519 verification from hex-encoded key and signature. |
| `HmacSigner` | Legacy symmetric signer for `AGENTBRAKE_SIGNING_KEY` deployments. Integrity-only, **not** third-party proof. |
| `resolve_signer_from_env()` | Build the process signer from environment configuration (key file, seed, or legacy HMAC key). |
| `key_id_for_public_key(public_key_bytes)` | The `key_id` embedded in receipts signed by the matching private key. |

## `agentbrake.export`

| Symbol | What it is |
|---|---|
| `build_export(rows, ...)` | Package a receipt chain into a self-contained bundle: entries + public key + signed head. |
| `verify_export(bundle, ...)` | Offline verification of an export bundle — signatures, chain integrity, signed head, Merkle root, optional rollback/consistency checks. Backs `agentbrake verify`. |
| `build_receipt_proof(rows, seq, ...)` | Extract one receipt with an RFC 6962 inclusion proof (selective disclosure). Backs `agentbrake prove`. |
| `verify_receipt_proof(proof, ...)` | Verify a single-receipt proof against a pinned public key, no full log needed. Backs `agentbrake verify-receipt`. |
| `build_head_statement(...)`, `sign_head_statement(...)`, `verify_head_statement(...)` | The signed "this chain has exactly N entries ending at hash H" commitment underlying an export. |
| `default_signer()` | The process signer used when no explicit signer is passed to `build_export`. |
| `write_export(bundle, path)` | Write a bundle as pretty-printed, human-diffable JSON. |
| `rows_from_jsonl(path)` | Load receipt rows from a `JsonlLedger` file. |
| `rows_from_db(path)` | Load the attestation chain from a server SQLite database. |
| `Check` | One named verification step with a verdict and human-readable detail, as returned in a verify/verify-receipt report. |

See [Verifiable receipts](../README.md#verifiable-receipts) for what a receipt proves and does not prove.

## `agentbrake.merkle`

RFC 6962 (Certificate Transparency) Merkle tree primitives backing selective
disclosure. Re-implementable from the RFC alone.

| Symbol | What it is |
|---|---|
| `leaf_hash(data)`, `node_hash(left, right)` | The domain-separated leaf and interior hash functions. |
| `tree_root(leaves)` | Merkle Tree Hash (MTH) over a list of leaf inputs. |
| `inclusion_proof(index, leaves)` | Audit path (PATH) for the leaf at `index`. |
| `verify_inclusion(leaf, index, ...)` | Verify a raw inclusion proof against a root. |
| `entry_leaf(entry)`, `root_for_entries(entries)`, `proof_for_entry(index, entries)`, `verify_entry_inclusion(...)` | Receipt-entry-shaped convenience wrappers over the primitives above. |

## `agentbrake.report`

| Symbol | What it is |
|---|---|
| `build_report(bundle, verification, ...)` | Build the structured compliance report from a verified export bundle. Backs `agentbrake report`. |
| `render_markdown(report)` | Render a `build_report()` result as a self-contained Markdown document. |

See [The compliance report](../README.md#the-compliance-report).

## `agentbrake.providers.cometapi`

Optional — requires `pip install py-agentbrake[cometapi]`; the core package
never imports this module. See [Real LLM cost tracking](../README.md#real-llm-cost-tracking-cometapi).

| Symbol | What it is |
|---|---|
| `complete(model, messages, ...)` | Make a CometAPI chat completion call, price it from real token usage, and record it into the active run in one step. |
| `track(response, model)` | Extract usage from an OpenAI-compatible response and price it, without touching run state. |
| `record(call)` | Push a priced `CometAPICall` into the active run's budget accounting. No-op with no active run. |
| `CometAPICall` | One priced LLM call: model, token counts (`None` if the response had no usage), `cost_usd`, raw response. |
| `DEFAULT_BASE_URL`, `API_KEY_ENV_VAR` | The default CometAPI endpoint and the environment variable (`COMETAPI_KEY`) the client reads. |

## CLI

`agentbrake --help` and `agentbrake <command> --help` are the source of
truth for flags. Commands: `keygen`, `export`, `verify`, `prove`,
`verify-receipt`, `report`. See [Verifiable receipts](../README.md#verifiable-receipts)
for the walkthrough of each.
