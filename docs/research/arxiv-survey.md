# ArXiv Research Survey: AgentBrake Security Hardening

**Date:** 2026-09-23  
**Research Phase:** 1 (Literature survey)  
**Scope:** 2025-2026 arXiv papers on LLM agent security, guardrails, and cryptographic enforcement  
**Source:** arXiv API queries (70+ papers screened, 13 selected)

---

## Executive Summary

This document catalogs arXiv research relevant to AgentBrake's mission: runtime circuit-breaking, enforcement, and cryptographic proof for autonomous LLM agents. The survey was conducted as part of Phase 1-3 development work to:

1. **Identify latest academic advances** that could enhance AgentBrake
2. **Map implemented features** to published research (validation)
3. **Roadmap medium-term improvements** based on peer-reviewed foundations
4. **Document trade-offs** between adoption complexity and security gain

**Key Finding:** AgentBrake's core mechanisms (taint tracking, flow blocking, signed receipts, delegation tokens) align with published research in OWASP Agentic AI Top 10 (2026) and align with academic proposals for cryptographic accountability in multi-agent systems.

---

## Papers Analyzed: IMPLEMENTED NOW (Phase 3)

### ✅ #3: Cryptographically Verifiable Authorization for Autonomous AI Agents
- **arXiv ID:** 2607.21325v2
- **Published:** 2026-07-23
- **Status:** **IMPLEMENTED** ✅
- **What They Do:**
  Formalizes agent authorization as cryptographically verifiable relation binding (principal, request, context, policy). Proposes Groth16 zero-knowledge proofs to externally verify that a decision was made under stated policy.
- **AgentBrake Fit:**
  Receipts now include `policy_digest` field (SHA256 hash of the flow policy applied). Receipt proves "we stopped this exfiltration attempt under policy X" — not just "we stopped something." Auditor can independently hash their copy of the policy and verify the receipt was issued under that exact policy.
- **Implementation Cost:** ✅ **Done** (1 session)
  - Added `FlowPolicy.to_dict()` to serialize policy deterministically
  - Added `policy_digest()` function in `receipts.py`
  - Flow and delegation receipts now include optional `policy_digest_value` field
  - Backward compatible: field is optional, old receipts still verify

### ✅ #4: Hardware Keystores for AI Agent Signing (Zero-Trust MCP Enforcement)
- **arXiv ID:** 2608.06130v1
- **Published:** 2026-08-06
- **Status:** **IMPLEMENTED** ✅
- **What They Do:**
  Five-layer enforcement combining session identity, scope bounds, semantic validation, taint tracking, and tamper-evident accountability for agent cryptographic operations. Advocates hardware-confined key material.
- **AgentBrake Fit:**
  Created pluggable `KeyStore` protocol enabling swappable storage backends (in-memory, file, future HSM). `InMemoryKeyStore` for testing, `FileKeyStore` for development. Scope bounds can be added: delegated sub-agents can only sign operations within their delegated scope.
- **Implementation Cost:** ✅ **Done** (2 sessions)
  - New `KeyStore` protocol (3 methods: load, save, exists)
  - `InMemoryKeyStore` implementation (ephemeral, testing-friendly)
  - `FileKeyStore` implementation (PEM files, persistent, auto-gen in dev)
  - No changes to public API; existing signing.py paths unchanged

### ✅ OWASP Quick Wins: Detector Receipts + Micro-Dollar Accounting
- **Referenced:** OWASP Agentic AI Top 10 (2026)
- **Status:** **IMPLEMENTED** ✅
- **What:**
  1. **Signed receipts for all detector blocks** (budget/loop/escalation/timeout) — not just flow/delegation
  2. **Integer micro-dollar accounting** — replace float USD with int micro-dollars (1M µ$ = 1 USD)
- **AgentBrake Fit:**
  - New `build_detector_attestation()` and `mint_detector_receipt()` functions
  - Budget/loop/escalation/timeout blocks now produce cryptographically signed receipts
  - Cost tracking is exact-integer to prevent rounding attacks
  - Receipts include detector context (total_cost, call_count) for audit
- **Implementation Cost:** ✅ **Done** (3 sessions)
  - Backward-compatible: `ToolCall.cost_usd` (float property) still works, stores as `cost_usd_micro` (int)
  - All 240 tests pass
  - Test suite updated to verify detector receipts are minted and signed

---

## Papers Analyzed: ROADMAP (Medium-Term, Significant Work)

### 🟡 #5: NiyamAI — Intent-Bound AI Agent with Cryptographic Guardrails (zkSNARK)
- **arXiv ID:** 2608.07167v2
- **Published:** 2026-08-07
- **What They Do:**
  Produces zkSNARK proofs certifying correct policy evaluation for agent decisions. A verifier can confirm a decision was made under the stated policy *without seeing the policy details*. Non-interactive, post-hoc verifiable.
- **AgentBrake Fit:**
  Current receipts prove "we applied policy digest X." ZK proofs add "we evaluated policy X correctly *without revealing it*." High value for compliance audits — external auditor gets proof without needing proprietary policy details.
- **Roadmap Rationale:**
  - **Value:** Enables third-party verification of policy application without exposing policy source
  - **Cost:** 3-4 sessions (circom library integration, trusted ceremony for keys, ~100ms proof generation per block)
  - **Trade-off:** Proof generation latency vs. compliance value; not critical for MVP
- **Blockers:** Requires trusted setup (one-time per key; can use ceremony from alt project)

### 🟡 #6: Zero-Knowledge Predicate Proofs Between AI Agents
- **arXiv ID:** 2608.30083v1
- **Published:** 2026-08-30
- **What They Do:**
  ZK gateway enabling agents to exchange cryptographic proofs of policy compliance instead of raw context. Agent A can delegate to Agent B while passing "context satisfies policy P" proof instead of context data itself. Measured in Kubernetes: 6.2ms proof generation.
- **AgentBrake Fit:**
  Current delegation tokens embed scope and intent, but sub-agent sees full context. ZK version: sub-agent receives only proof that context meets policy, reducing exfiltration surface. Unlocks "blind delegation."
- **Roadmap Rationale:**
  - **Value:** Reduces context leakage in multi-agent chains; enabling safer sub-agent delegation
  - **Cost:** 3-4 sessions (architectural, new inter-agent communication layer)
  - **Trade-off:** Complexity vs. privacy gain; not urgent for 2-agent systems
- **Blockers:** Requires refactored agent communication protocol

### 🟡 #7: Delegation Without Trust — Authorization Broker for Untrusted Models
- **arXiv ID:** 2609.00267v1
- **Published:** 2026-08-31
- **What They Do:**
  Authorization broker containing compromised agent behavior via structural isolation. Reduces reachable actions from 8,100 to 1.5 mean for a malicious sub-agent through compartmentalization.
- **AgentBrake Fit:**
  Current delegation trusts the sub-agent is honest. Compartment-based isolation adds assumption: "agent can be malicious; isolation bounds harm." Implementation: sub-agents run in tool-call namespaces; cross-compartment calls require signed authorization.
- **Roadmap Rationale:**
  - **Value:** Defense-in-depth against compromised sub-agents
  - **Cost:** 2-3 sessions (agent graph refactoring into compartments)
  - **Trade-off:** Architectural change vs. practical gain for red-team scenarios
- **Blockers:** Requires multi-level tool namespace design

### 🟡 #8: Authorization Architectures for Tool-Using AI Agents (Comprehensive Review)
- **arXiv ID:** 2609.15906v1
- **Published:** 2026-09-14
- **What They Do:**
  Meta-review of 5 interdependent authorization layers for tool-using agents (identity, intent, context, capability, audit). Proposes 7 structural requirements and 4-layer reference architecture.
- **AgentBrake Fit:**
  AgentBrake currently implements 3 layers (allow-list = capability, delegation tokens = intent + identity, flow = context). Paper identifies 2 missing: *context-aware intent* (agent adapts allowed tools based on context) and *temporal revocation* (token TTL is only mechanism).
- **Roadmap Rationale:**
  - **Value:** Architectural clarity; no immediate feature but guides future design
  - **Cost:** 1 session (planning document, code review against framework)
  - **Trade-off:** Documentation and architectural alignment, no risk
- **Blockers:** None; can be done anytime

---

## Papers Analyzed: NOTED FOR FUTURE (Research, Not Actionable Now)

### 🔵 #9: BenchShield — Formal Model-Backed Instrumentation for Reward Integrity
- **arXiv ID:** 2609.11028v1
- **Published:** 2026-09-10
- **Why Later:** Addresses reward hacking in *agent benchmarks*, not agent enforcement. Useful when running AgentBrake-governed agents through eval harnesses, but not a feature AgentBrake itself needs.
- **Future Use:** Defensive tool for validating AgentBrake test cases aren't being gamed by an agent.

### 🔵 #10: Forgetting Without Restarting — Execution-State Unlearning for Stateful Agents
- **arXiv ID:** 2609.04875v1
- **Published:** 2026-09-04
- **Why Later:** Enables agents to "forget" sensitive data without full restart through provenance-guided selective replay. Requires AgentBrake to manage durable state (checkpoints, WAL). MVP assumes single-run agents.
- **Future Use:** Support long-lived agents that must securely clear context mid-run.

### 🔵 #11: Trust Propagation in Multi-Agent LLM Pipelines
- **arXiv ID:** 2609.17648v1
- **Published:** 2026-09-15
- **Why Later:** Privilege escalation study in 4-agent chains; isolation boundaries contain compromised agents. Requires multi-hop agent graph support with per-edge authorization. AgentBrake's delegation token is single-hop.
- **Future Use:** Multi-level agent hierarchies (Agent A → B → C) with trust attenuation per hop.

### 🔵 #12: Recoverability as a System Primitive for Long-Horizon Agents
- **arXiv ID:** 2609.13672v1
- **Published:** 2026-09-12
- **Why Later:** Resumption after interruption requires saved checkpoints and validated recovery. AgentBrake's receipt chain proves enforcement decisions but doesn't manage resumption policy. Relevant for long-running agents.
- **Future Use:** Safe agent resumption after human-approved override or timeout.

### 🔵 #13: Toward Secure AI-Powered Penetration Testing Agents
- **arXiv ID:** 2609.16694v1
- **Published:** 2026-09-15
- **Why Later:** Specialized threat model (autonomous pentesting with expected-to-fail actions). Good validation case for AgentBrake in offensive security context, but not a feature driver now.
- **Future Use:** Reference implementation for pentester agents with budget + allow-list guardrails.

---

## Summary Table: Implementation Status

| Paper | Feature | Phase 3 Status | Roadmap | Note |
|-------|---------|---|---|---|
| #3 | policy_digest in receipts | ✅ DONE | — | Backward compatible; optional field |
| #4 | KeyStore abstraction | ✅ DONE | — | FileKeyStore, InMemoryKeyStore ready; HSM future |
| OWASP | Detector receipts | ✅ DONE | — | budget/loop/escalation/timeout now signed |
| OWASP | Micro-dollar accounting | ✅ DONE | — | Integer cost; float properties for compat |
| #5 | ZK policy proofs | — | 🟡 3-4 sessions | Compliance audits; proof generation latency |
| #6 | ZK inter-agent communication | — | 🟡 3-4 sessions | Blind delegation; privacy gain |
| #7 | Compartmented isolation | — | 🟡 2-3 sessions | Defense against malicious sub-agents |
| #8 | Authorization review + planning | — | 🟡 1 session | Architectural alignment document |
| #9-13 | Future research | — | — | Eval harnesses, long-lived agents, hierarchies |

---

## Key Takeaways

1. **AgentBrake's foundations are sound:** Flow taint tracking, signed delegation, and receipts align with published academic work on agent accountability.

2. **Crypto is the frontier:** ZK proofs (#5, #6) and cryptographic policy binding (#3) represent the next wave. AgentBrake now has `policy_digest` (crypto-binding), making ZK proofs (#5) a natural evolution.

3. **Receipts as audit trail:** Extending signed receipts to *all* detector blocks (budget/loop/escalation) was a high-ROI OWASP quick win. Any agent interruption now leaves cryptographic proof.

4. **Integer accounting matters:** Micro-dollar accounting (#OWASP) eliminates float rounding as an attack surface. Simple, high-value hardening.

5. **Roadmap is clear:** #5 and #6 (ZK proofs) are the next priority if compliance audits become a driver. #7 (compartments) addresses red-team concerns. #8 (auth review) is planning-only, always valuable.

---

## References

- arXiv:2607.21325v2 — Cryptographically verifiable authorization
- arXiv:2608.06130v1 — Hardware keystores for agent signing
- arXiv:2608.07167v2 — NiyamAI (zkSNARK guardrails)
- arXiv:2608.30083v1 — Zero-knowledge predicate proofs between agents
- arXiv:2609.00267v1 — Delegation without trust
- arXiv:2609.15906v1 — Authorization architectures for tool-using agents
- OWASP Agentic AI Top 10 (2026) — LLM security standards

---

**Next Steps:**
- Monitor arXiv for 2026-2027 papers on:
  - Multi-agent authorization (credential chains)
  - Cryptographic escrow for agent keys
  - Formal verification of delegation scopes
- Evaluate #5 (zkSNARK) for compliance roadmap
- Consider #7 (compartments) for hostile-environment deployments
