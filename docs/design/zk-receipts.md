# Design spike: zero-knowledge receipts

**Status:** exploration. Nothing here is implemented, scheduled, or promised.
No file under `agentbrake/` was changed to write this, and `pyproject.toml`
gained no dependency.

**Question.** AgentBrake's receipts are Ed25519-signed and hash-chained. In
local mode the private key lives in the agent's own process, so a fully
compromised agent can read the key and forge receipts — a limitation
[`signing.py`](../../agentbrake/signing.py) already states out loud. The
NiyamAI paper (arXiv 2608.07167) proposes proving *that the policy evaluation
happened and produced this result* with a zkSNARK instead of signing the
result, which is meant to survive a compromised host. Does that fit AgentBrake,
and what would it cost?

**Answer, in one paragraph.** The deterministic core of AgentBrake is genuinely
expressible as an arithmetic circuit — more easily than NiyamAI's neural Judge,
because a threshold comparison is cheaper than a forward pass. A working proof
of `BudgetDetector`'s predicate is in [§8](#8-prototype). But ZK does not solve
the problem the spike was opened for. A SNARK proves a computation was
performed correctly *on the witness the prover supplied*. A compromised host
that can forge a signature can equally well supply a fabricated witness and
obtain an honest proof of a fabricated decision. **ZK moves the trust boundary
from "the code ran honestly" to "the inputs were honest" — it does not remove
it.** The inputs are the unsolved problem, and they are equally unsolved in
both designs. Meanwhile it costs ~5,700× on proving, ~380× on verification, a
138 MB proving key, and — the part that actually matters here — the
one-command offline verification story. Not now. The conditions under which
that changes are in [§6](#6-what-would-make-this-the-right-priority).

**Provenance.** arXiv 2608.07167 postdates this author's reading. Every
NiyamAI figure below (1.7 s prove, 51 ms verify, 18.6 KB, 431 constraints,
11→8 Judge network, EZKL + Halo2/KZG) is quoted from the spike request as
given and has **not** been independently checked. Every AgentBrake and EZKL
figure was measured on this machine and is reproducible.

---

## 1. Where the trust boundary actually is today

Read: [`receipts.py`](../../agentbrake/receipts.py),
[`signing.py`](../../agentbrake/signing.py),
[`flow.py`](../../agentbrake/flow.py), plus
[`server/attest.py`](../../agentbrake/server/attest.py) and the guard loop in
[`__init__.py`](../../agentbrake/__init__.py), where the three meet.

### 1.1 What is inside the boundary

In local mode, one address space holds all of:

| Thing | Where |
|---|---|
| The detector chain | `__init__.py:448-458` |
| `RunState` — the call history and taint set the detectors read | `types.py:44-57` |
| The ledger receipts land in | `receipts.py:60-116` |
| **The Ed25519 private key** | `attest.SIGNER`, a module global resolved from the environment at import time (`server/attest.py:95`) |

`mint_flow_receipt` → `_seal_and_append` → `attest.sign_body` all execute in
the guarded agent's process, under that global signer. The agent process is
the entire TCB: it decides, it narrates the decision, and it signs the
narration.

One detail worth stating plainly, because the opposite is easy to assume:
**remote mode does not move flow receipts out of the agent process.** Remote
mode moves the *human decision* out — `_handle_remote_interrupt`
(`__init__.py:365`) posts to the server and the server's own
`record_decision` signs the approval with the server's key. But the autonomous
block receipt is minted at `__init__.py:505` unconditionally, using whatever
key the *agent's* process resolved. A deployment that believes "remote mode
signs on a trusted host" is half right.

### 1.2 What a receipt proves today

From `build_flow_attestation` (`receipts.py:132`) and the chain primitives in
`attest.py`:

1. **Authorship under a key.** Ed25519 over `DOMAIN_ATTESTATION_V2 ||
   canonical_json(body)`. Someone holding the private key for `key_id`
   produced these exact bytes.
2. **Non-alteration since signing.** Any edit breaks the signature.
3. **No silent insertion, deletion or reordering *among the rows shown*.**
   `prev_hash` / `entry_hash` chaining.
4. **No cross-context or cross-chain replay.** Domain separation plus
   `chain_id`.
5. **Binding to one specific call.** `tool_args_digest =
   sha256(canonical_json({tool, args}))`; `info_digest` over the `flow`
   payload.
6. **That overrides were recorded too.** `mint_flow_override_receipt` puts
   human approvals in the same chain as the blocks, so the
   most-worth-auditing event leaves a trace rather than a gap.

### 1.3 What a receipt does not prove — the interesting part

* **That the detector ran at all.** The signature covers a *claim*: "a flow
  block occurred, with this sink and these taints". It is not evidence that
  `FlowRuleDetector.check` was invoked, or that `RunState.taints` reflected
  real calls. Nothing in the signed body is derived from execution; it is all
  derived from values the signing process chose.
* **Which policy was in force.** `build_flow_attestation` embeds the *outcome*
  (`sink`, `sink_category`, `violated_taints`, `tainted_by`) but there is no
  digest of the `FlowPolicy` anywhere in the attestation, and none of the
  detector configuration. An auditor holding a perfectly valid chain cannot
  tell whether `budget_usd` was $1 or $1,000,000, whether
  `LoopDetector.threshold` was 3 or 300, or whether the deny set actually
  contained `("untrusted", "egress")`. **This is a real gap, it has a cheap
  fix, and it has nothing to do with ZK** — see [§7](#7-cheaper-things-that-buy-most-of-the-value).
* **That the chain is complete.** Truncating the tail, or dropping the log
  before it is persisted, leaves a chain that still verifies. `attest.py` says
  so; the signed chain head in `export.py` is what bounds it.
* **Anything at all, if the private key leaked.** A process that can read the
  seed can mint a complete, internally consistent, fully verifying alternative
  history.

### 1.4 Which decisions are deterministic

Every `check()` in the chain, in execution order:

| Detector | Decision rule | Deterministic? | Arithmetizable? |
|---|---|---|---|
| `DelegationDetector` (`delegation.py`) | `token.is_expired()` **or** `name not in allowed_tools` | Partly | Set membership yes. **Expiry no** — needs a trusted clock, which no circuit can supply |
| `EscalationDetector` (`detectors.py:190`) | `name not in allowed_tools` | Yes | Yes — membership against a committed list |
| `FlowRuleDetector` (`flow.py:203`) | map lookup `sink_category_for`, union of active taints, filter against `deny` pairs | Yes | **Yes, cleanly** — all discrete lookups over small committed sets |
| `LoopDetector` (`detectors.py:101`) | last N−1 calls share `_structural_hash` | Yes | Partly — the comparison is trivial, **SHA-256 in-circuit is the dominant cost**, and `json.dumps(..., default=str)` is not expressible in a field at all |
| `RetryStormDetector` (`detectors.py:156`) | same-tool count in a window, minus `_looks_like_progress` | Yes | Partly — counting and monotonicity are fine; `isinstance(v,(int,float)) and not isinstance(v,bool)` is Python type introspection, and the distinct-ratio needs the same hashes |
| `BudgetDetector` (`detectors.py:177`) | `total_cost_usd + cost_usd > budget_usd` | Yes | Yes — modulo floats. Proved end to end in §8 |

Two cross-cutting obstacles fall out of that table.

**Floats.** `ToolCall.cost_usd` and `RunState.total_cost_usd` are `float`
(`types.py:39`, `types.py:46`). A SNARK works over a prime field; there are no
floats. Fixed-point encoding is the standard bridge and is exactly where
soundness bugs live — two spends differing below the scale become equal
in-circuit. Any real implementation must quantize AgentBrake's cost type to
integers first. That is a public API change, not a circuit detail. (§8 shows
the upside: once the values *are* integers, fixed-point can be switched off
entirely and the circuit becomes exact.)

**Canonicalization.** `_structural_hash` and `sink_call_digest` both run
`json.dumps` over caller-supplied `args`, with `default=str` on the lenient
path — i.e. arbitrary Python `__str__`. That cannot be arithmetized. The only
option is to canonicalize outside the circuit and feed the digest in as a
public input, which means the canonicalization is *not* proved. A trust gap
reintroduced at exactly the seam ZK was meant to close.

### 1.5 Which parts would depend on a neural model

**None.** This is the load-bearing finding of Phase 1.

NiyamAI proves a Judge network's forward pass because *their* policy engine is
a neural network. AgentBrake's policy engine is a few dozen lines of `if`.
Two consequences:

* The EZKL/ONNX pipeline — the half of NiyamAI's stack that exists to turn a
  trained model into a circuit — is **not needed**. A hand-written circuit
  (Halo2, Circom, Noir) for a taint-flow lookup would be far smaller than 431
  constraints.
* The quoted 431 constraints is therefore not a useful ceiling in either
  direction. §8 measures a circuit doing *61 rows* of real work and it costs
  the same order as NiyamAI's — because at this scale the cost is the proof
  system, not the computation.

There is one place a model could plausibly enter later — a learned classifier
for "is this text a prompt injection" — but AgentBrake deliberately does not
have one. Its design bet is that deterministic structural rules beat a
classifier for this job. Adding a neural Judge *in order to have something
worth proving in ZK* would be the tail wagging the dog.

---

## 2. The threat model ZK addresses

Stated as an attacker with a capability, not as a vibe.

**Attacker:** arbitrary code execution inside the agent process, at the same
privilege as AgentBrake. Concretely: a malicious dependency, a compromised
tool implementation, an RCE in the agent host.

**Against Ed25519 receipts.** The attacker reads the seed out of
`Ed25519Signer._private_key`, or `AGENTBRAKE_SIGNING_SEED` out of the
environment, and mints a chain saying whatever it likes: that an exfiltration
was blocked when it was allowed, that a run made three calls when it made
three hundred. The chain verifies perfectly under the published public key.
Every property in §1.2 collapses at once, because all six reduce to "someone
with the key said so". **AgentBrake documents this and does not defend against
it.**

**Against ZK receipts.** There is no key to steal. A proof is checked against
a verification key the attacker cannot influence, so the attacker cannot
produce a proof of a computation the circuit does not describe. If the circuit
says "blocked ⟹ a denied taint was active", no block can be proved without an
active denied taint. That property is real, and Ed25519 does not have it.

### What ZK does not fix

The attacker does not need to break soundness. **It supplies the witness.**

The circuit's inputs — the call history, the accumulated cost, the active
taint set — are computed in the same compromised process. The attacker feeds
`taints = {"untrusted"}` for a run where nothing untrusted was ever read and
gets a perfectly sound proof of a block that never needed to happen. Or feeds
a truncated call list and proves the budget was never exceeded. The proof is
honest. The premises are fiction.

The accurate statement:

> Ed25519 requires trusting that the agent process computed **and reported**
> honestly. ZK narrows that to trusting the agent process computed its
> **inputs** honestly. It narrows the boundary; it does not remove it.

Whether the narrowing is worth anything depends entirely on whether the inputs
can be attested by something outside the host — signed tool-call transcripts
from an MCP server, a co-signing egress gateway, a TEE, a provider API signing
its own usage numbers. **Without input attestation, ZK buys AgentBrake close
to nothing over Ed25519 for the compromised-host threat model.** Input
attestation is the prerequisite, and it is the harder problem.

### The threat model where ZK wins outright

There is one, and the spike request does not mention it: **confidentiality**.

To convince an auditor today, a receipt must *show* them the facts — which
sink, which taints, which source tool, and via the export bundle, the run. A
ZK proof can establish a predicate while revealing nothing else:

* "No denied flow occurred anywhere in this run" — without disclosing a single
  tool call.
* "Cumulative spend stayed under the contractual cap" — without disclosing
  per-call costs or which models were used. (§8 does exactly this.)
* "Every call stayed inside the delegated scope" — without disclosing the
  scope to a third party who is not the delegator.

Ed25519 cannot do any of these at any price. This is a genuine capability gap;
it does **not** depend on input attestation landing first (the verifier already
accepts the prover's facts in this framing — they simply should not get to
*read* them); and it maps onto AgentBrake's existing
[`delegation.py`](../../agentbrake/delegation.py) cross-organizational story
far better than the compromised-host story does.

If ZK ever ships in AgentBrake, this is the reason it should, not the one in
the spike request.

---

## 3. What in AgentBrake would be provable

Ranked by security value per unit of circuit pain.

### Tier 1 — clean fit

**Flow rule evaluation** (`FlowRuleDetector.check`). Intern taint labels and
sink categories to field elements; commit to `_sources`, `_sinks` and
`_denied` as a Merkle root; prove `(label, category) ∈ denied ∧ label ∈
active_taints`. Discrete, tiny, security-relevant, and it is the decision that
already mints a receipt. This is the circuit to write if one gets written.

**Budget threshold** (`BudgetDetector.check`). One sum, one comparison, once
costs are integers. Proved end to end in §8. Note it produces **no receipt
today at all** (§7.2), so proving it in ZK would mean building the receipt
first.

**Allow-list membership** (`EscalationDetector.check`). Merkle membership
against a committed tool list. Trivial — and the same commitment closes the
missing-policy-digest gap from §1.3 for free.

### Tier 2 — possible, expensive, partly dishonest

**Loop and retry-storm detection.** The comparison logic arithmetizes fine.
The cost is SHA-256 over every call in the window. The *honesty* problem is
that the JSON canonicalization cannot be in the circuit, so the proof
establishes "these digests satisfy the loop predicate" with the mapping from
real calls to digests left unproved. A proof that assumes away the interesting
part is easy to mistake for one that doesn't.

**Aggregate run properties.** "Across N calls, no detector fired." This is
where succinctness finally earns something — one small proof instead of N
receipts — but it needs recursion or an in-circuit loop over the history, and
the per-step accumulator (`total_cost_usd`) must be carried as a committed
public value between steps. None of the quoted per-proof figures cover this.

### Tier 3 — out of reach

**Delegation expiry.** `token.is_expired()` compares against the wall clock. A
circuit has no clock and cannot get one; time must arrive as a signed input
from a timestamping authority — a trusted third party, which is the exact
thing ZK was brought in to avoid.

**Anything touching raw `args`.** Free-form `Dict[str, Any]` with `default=str`
serialization. Not a field element in sight.

**The unguarded path.** `flow.py`'s docstring is already explicit: a sink
reached through an undeclared tool is invisible to the engine. A proof about
declared tools says nothing about undeclared ones, and its air of rigor makes
that omission *more* dangerous, not less.

---

## 4. What it would cost

All AgentBrake and EZKL numbers measured on this machine (Windows 11, Python
3.13, `ezkl` 23.0.5). See §8 for the harness.

### 4.1 Latency

| Operation | Ed25519 today | Measured EZKL | NiyamAI (quoted) |
|---|---|---|---|
| Produce one receipt / proof | **0.42 ms** | **2.41 s** | 1.7 s |
| Verify | **0.13 ms** | **50 ms** | 51 ms |
| One-time setup (per circuit) | none | 1.90 s + 0.39 s SRS fetch | not stated |

≈ 5,700× on proving, ≈ 380× on verification.

The saving grace is volume. Receipts are minted **only on a block or an
override** (`__init__.py:504-521`), never on every call — a run that behaves
produces zero receipts. Paying 2.4 s at the moment you are already halting the
agent is defensible: you are about to wake a human anyway. What is *not*
affordable is proving the negative — "no rule fired on any of these 300 calls"
— one call at a time; that needs aggregation or recursion.

### 4.2 Size

| Artifact | Bytes | Who needs it |
|---|---|---|
| Signed attestation body | 731 | — |
| Full stored receipt row | **1,996** | verifier |
| `receipt_summary` on an interrupt | 1,109 | — |
| EZKL `proof.json` | **17,480** | verifier |
| EZKL `vk.key` | 66,823 | verifier, once per circuit |
| KZG SRS | 4,194,564 | verifier, once |
| EZKL `pk.key` | **138,479,371** | **prover — i.e. shipped to every agent host** |

The proof itself is ~9× the stored row, and lands within 6% of NiyamAI's
quoted 18.6 KB. The 138 MB proving key is the number nobody quotes and the one
that decides deployment: it has to exist wherever the agent runs.

### 4.3 The cost is not the computation

The most useful thing the prototype measured:

| | NiyamAI Judge | AgentBrake budget check |
|---|---|---|
| What is proved | 11→8 neural forward pass | one `ReduceSum`, one `Sub` |
| Circuit work | 431 constraints | **61 rows** |
| Circuit allocated | not stated | **2^15 = 32,768 rows** (99.8% padding) |
| Prove | 1.7 s | 2.41 s |
| Verify | 51 ms | 50 ms |
| Proof | 18.6 KB | 17.5 KB |

A predicate roughly an order of magnitude simpler costs **the same**. At this
scale the price is the proof system's floor, not the computation. So:

* The "our detectors are simple, so the circuit will be cheap" intuition is
  **wrong**. It would be right at a scale AgentBrake is nowhere near.
* Conversely, there is enormous headroom: AgentBrake could prove something far
  richer than a threshold for the same 2.4 s. If ZK is ever adopted, proving
  *one* comparison would be leaving the whole budget on the table.

### 4.4 Dependencies

* `ezkl` 23.0.5 — a 12.1 MB `cp37-abi3-win_amd64` wheel. **No Rust toolchain
  required**: there is none on this machine and the install succeeded anyway.
  The "you'll need Rust" objection is wrong for the common platforms and
  should not be used as an argument.
* The ONNX route additionally needs `onnx` and `numpy`, dragging in protobuf.
  Hand-writing the circuit would drop these — and since AgentBrake has no
  neural model (§1.5), hand-writing is the right route anyway.
* A KZG structured reference string, 4.2 MB, fetched at setup. It must be
  pinned and distributed, and a substituted SRS is a *silent* soundness
  failure.
* Proving and verification keys, per circuit, per version.
* API stability is poor. Writing §8 hit
  `TypeError: 'WindowsPath' object cannot be cast as 'str'` from
  `calibrate_settings` while `Path` was accepted elsewhere; `prove()`'s
  positional signature differs from its own docstring's ordering across
  versions; several entry points changed between sync and async across
  releases. This is research software. AgentBrake's current runtime
  dependencies are `httpx`, `pydantic`, `cryptography`.

It would have to be an optional extra — `py-agentbrake[zk]` — never core. The
package targets `requires-python >=3.9` across platforms. `cryptography` is
everywhere; `ezkl` is not.

### 4.5 Developer and auditor experience — the real cost

This is where the idea breaks, and it is not a performance argument.

AgentBrake's proposition today is one sentence: *here is a JSON bundle and a
64-hex-character public key; verify it yourself, offline, trusting nobody.*
`verify_export` needs nothing else.

The ZK version of that sentence: *here is a proof, a verification key, a
settings file, a 4 MB structured reference string, and you will need the
matching version of a Rust-backed prover runtime; also, when we change the
circuit every key you pinned becomes invalid, and telling a legitimate circuit
upgrade apart from an attacker substituting a weaker circuit is now your
problem.*

Circuit versioning is not a footnote. It needs a `circuit_digest` in every
receipt, a published registry of circuit versions, and a verifier policy for
unknown digests — infrastructure that must be built and *trusted*, which
reintroduces a trusted party at the top of a system whose whole selling point
was not having one.

An auditor who can run `agentbrake verify bundle.json --public-key <hex>` is
an auditor who verifies. An auditor who must install a toolchain is an auditor
who takes your word for it. **A weaker proof that gets checked beats a
stronger proof that doesn't.**

---

## 5. Why this is not the right priority today

Five reasons, strongest first.

1. **It does not close the hole it was opened for.** §2: a compromised host
   forges the witness instead of the signature. Without input attestation —
   which AgentBrake does not have, and which is strictly harder — ZK swaps one
   unverifiable assumption for another and charges 5,700× latency for the
   trade.

2. **The prerequisite is a different project.** The honest ordering is (a)
   attest the inputs, (b) commit to the policy in receipts, (c) *then* consider
   proving the evaluation. (a) and (b) deliver value on their own and are
   needed whether or not (c) ever happens. (c) alone delivers almost nothing.

3. **There is a weakness in the existing proof story sitting in front of it.**
   §1.3: a valid receipt chain today does not tell an auditor what the budget
   cap or the deny set was. Fixable in a few lines, and strictly more urgent
   than any new proof system.

4. **The premise doesn't transfer.** NiyamAI proves a neural forward pass
   because its policy engine is a neural network. AgentBrake's is deterministic
   code. Half of NiyamAI's machinery (EZKL, ONNX, quantization) solves a
   problem AgentBrake does not have — and §4.3 shows their headline figures
   would not shrink even if it did.

5. **No one has asked.** No user, no compliance requirement, no integration
   currently blocked on this. Building cryptographic infrastructure ahead of a
   named consumer is how a project acquires a maintenance burden with no
   corresponding users.

---

## 6. What would make this the right priority

Any one of these moves it onto the roadmap. All are *external* signals,
deliberately — none is "we felt like it".

**A verifier who does not trust the operator's host, and says so in writing.**
Regulated logging where the operator is the party under scrutiny: EU AI Act
high-risk record-keeping, financial pre-trade approval, clinical decision
audit. The distinguishing feature is not "security-conscious" — it is that the
*relying party is not the operator*.

**A confidentiality requirement.** §2's last section. A customer who must
prove "no denied flow occurred" to a counterparty they cannot show the tool
calls to. This is the strongest trigger, because Ed25519 cannot be stretched
to cover it at any price and — unlike the compromised-host case — it does not
wait on input attestation. Watch for it in cross-organizational delegation,
where [`delegation.py`](../../agentbrake/delegation.py) already models a
delegator and a delegatee in different trust domains.

**An on-chain or smart-contract verifier.** If a contract must check that an
agent respected its mandate before releasing funds, 50 ms and 17.5 KB is the
*native* cost model and "Ed25519 plus a human auditor" is not an option. Agent
payment rails are the plausible path.

**Input attestation arriving from elsewhere.** If signed tool-call transcripts
become normal — an MCP server signing what it served, a provider signing its
own usage numbers, a co-signing egress gateway — then §2's premise problem is
solved by someone else and ZK's value jumps from "almost nothing" to "the
obvious next layer". This is the one to watch: it is not under this project's
control, and it flips the whole analysis when it lands.

**Explicit non-triggers.** Not: a well-cited paper. Not: a competitor's
announcement. Not: "ZK would look impressive on the README". The asymmetry
matters — shipping crypto nobody verifies is *worse* than shipping none,
because it converts an honest documented limitation into an implied guarantee.

---

## 7. Cheaper things that buy most of the value

Each is smaller than a circuit and addresses a gap §1 actually found. Listed
because a design spike that returns only "no" is a wasted spike.

1. **Commit to the policy in the receipt.** Add `policy_digest =
   sha256(canonical_json({sources, sinks, denied, budget_usd, allowed_tools,
   loop_threshold, …}))` to `build_flow_attestation`. Closes §1.3: an auditor
   can then check the policy in force was the policy agreed to. Highest-value
   change in this document, roughly ten lines — and a prerequisite for any ZK
   design, since the circuit needs the same commitment.

2. **Mint receipts for loop, budget and escalation blocks.** Today only `FLOW`
   and `DELEGATION` produce receipts (`__init__.py:504-521`); a budget block in
   local mode raises `AgentBrakeInterrupt` and leaves no cryptographic trace at
   all. "We stopped the runaway agent at $0.50" is exactly the claim a customer
   will want to prove, and it is currently unprovable — with or without ZK.

3. **Document that remote mode still signs flow receipts locally** (§1.1), or
   change it so remote mode mints them server-side. The current behaviour is
   defensible; the gap between it and what a reader will assume is not.

4. **Quantize costs to integers.** `cost_usd` in micro-dollars rather than
   `float` removes an accumulating-rounding class of bug in `BudgetDetector`
   today, and is a hard prerequisite for any arithmetic circuit later. §8 shows
   the payoff is immediate in-circuit: with integral inputs, fixed-point can be
   switched off and the circuit is *exact*.

5. **Make chain-head anchoring a documented ritual.** `export.py` already signs
   a chain head. The truncation attack in §1.3 is bounded only if the head
   actually reaches the auditor on a schedule. A docs and CLI-ergonomics
   problem, not a crypto problem.

Items 1, 2 and 4 are on the path to ZK. Doing them is not a detour.

---

## 8. Prototype

[`experiments/zk_budget_proof.py`](../../experiments/zk_budget_proof.py) — a
standalone feasibility script, outside the package, with its own venv. Not
imported by anything, not in CI, dependencies not in `pyproject.toml`.

It proves in zero knowledge that a run's cumulative spend crossed a public
cap, **without revealing the individual call costs** — deliberately chosen to
demonstrate §2's confidentiality property rather than the compromised-host
one, since that is the property that survives scrutiny.

```
python -m venv experiments/.venv
experiments/.venv/Scripts/python -m pip install ezkl onnx numpy
experiments/.venv/Scripts/python experiments/zk_budget_proof.py
```

### Result

```
proof verified          : True
public output (margin)  : 50000        # micro-dollars over cap
  interpreted           : over_budget = margin > 0 = True
circuit size            : 2^15 rows (num_rows=61)

timings (s):          artifact sizes (bytes):
  gen_settings   0.01   pk.key          138,479,371
  calibrate      0.03   kzg.srs           4,194,564
  compile        0.00   vk.key               66,823
  get_srs        0.39   proof.json           17,480
  setup          1.90   budget.ezkl           1,499
  gen_witness    0.00   settings.json         1,170
  prove          2.41
  verify         0.05
```

Witness: eight prior call costs plus the new call, private. Public instance:
the cap and the verdict. Statement: `sum(costs) > cap`.

### What the prototype established

* **It works, and it is not hard.** Under an hour end to end, on Windows,
  with no Rust toolchain. The feasibility question is settled: *yes*.
* **Integer inputs let fixed-point be switched off.** Because the predicate is
  exact integer arithmetic rather than a forward pass, `input_scale = 0`
  produces a circuit with *zero* numerical error. NiyamAI's quantization
  machinery is simply unnecessary for this class of predicate. (The first
  attempt left EZKL's default scale on and the prover rejected the witness:
  `integer 409600000 is too large to be represented by base 16384 and n 2`.)
* **The cost is the proof system, not the predicate.** 61 rows of real work in
  a 32,768-row circuit — see §4.3.
* **The proving key is the deployment problem.** 138 MB per circuit, on every
  host that runs an agent.
* **The public output leaks more than the verdict.** This graph outputs the
  signed margin (`total − cap`), so the verifier learns the overage, not just
  the boolean. Hiding it needs the comparison in-circuit; ONNX `Greater`
  emits a bool tensor that EZKL's pipeline handles inconsistently across
  versions. A real implementation would write the circuit directly rather than
  going through ONNX — which, per §1.5, it should do anyway.

### What the prototype did not establish

That the costs it proved were real. The script picks its own witness. That is
§2's whole point, reproduced in miniature: the proof is sound and the premises
are whatever the prover said they were.

---

## 9. Ed25519 today vs. ZK tomorrow

| | **Ed25519 receipts (shipped)** | **ZK receipts (hypothetical)** |
|---|---|---|
| Decision was *reported* honestly | Yes, under key custody | Yes |
| Decision was *computed* honestly | **No** | Yes — for the computation in the circuit |
| The *inputs* were honest | **No** | **No** — same gap, unchanged |
| Survives a compromised agent process | **No** — the key is readable | **Partly** — no key to steal, but the witness is attacker-chosen |
| Proves which policy was in force | **No** (fixable, §7.1) | Yes, if the policy is a committed input |
| Proves a predicate without revealing the facts | **No** | **Yes** — the one unique capability |
| Detects tampering after the fact | Yes (signature) | Yes (unforgeable proof) |
| Detects deletion / reordering | Yes (hash chain) | Only with an accumulator design |
| Detects tail truncation | No — needs an anchored chain head | No — same, orthogonal |
| Covers undeclared tool paths | No | No — and looks like it might |
| Handles wall-clock expiry | Yes, trivially | **No** — needs a trusted time oracle |
| Produce | 0.42 ms | 2.41 s |
| Verify | 0.13 ms | 50 ms |
| Size on the wire | 2.0 KB row | 17.5 KB proof + 67 KB vk + 4.2 MB SRS |
| Prover-side artifacts | none | 138 MB proving key |
| Verifier needs | one JSON + 64 hex chars | proof + vk + settings + SRS + matching runtime |
| Runtime dependencies | `cryptography` | `ezkl` (12 MB wheel) + SRS + circuit registry |
| Any Python ≥3.9, any platform | Yes | No — optional extra at best |
| Upgrade safety | key rotation handled (`key_id`) | a circuit change invalidates every pinned vk |
| Honest one-liner | *"Someone with this key attested this."* | *"This computation was performed correctly on inputs I chose."* |

Read the last row twice. Neither says *"this is what happened."* Getting to
that sentence requires attesting the inputs, and neither scheme does it.

---

## 10. Conclusion

ZK receipts are feasible for AgentBrake's deterministic core — demonstrably so,
§8 — and the toolchain is more accessible than expected. They are also the
wrong answer to the question that motivated this spike: they relocate the trust
boundary from reporting to inputs rather than eliminating it, and they charge
for the move in latency, artifacts, and the one-command offline verification
story that is the project's actual differentiator.

The right next moves are the cheap ones in §7 — commit the policy, receipt
every block, quantize costs. They strengthen the proof story that exists, are
worth doing regardless, and happen to lie on the path if §6's triggers ever
fire.

Revisit when a trigger is met, not on a schedule.

---

## References

* `agentbrake/signing.py` — "Honest limitations": the local-key caveat this
  spike started from.
* `agentbrake/server/attest.py` — chain semantics and their documented limits.
* `agentbrake/flow.py` — the taint engine's own list of what it cannot see.
* `SECURITY.md` — the project's standing threat-model statement.
* NiyamAI, arXiv 2608.07167 — **not independently verified**; all figures
  quoted from the spike request.
