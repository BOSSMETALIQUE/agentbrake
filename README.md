with open("README.md", "r", encoding="utf-8") as f:
    txt = f.read()

# 1. ASI03: Roadmap -> Covered
old_asi03 = "| **ASI03** | Identity Abuse | Signed delegation tokens bind the original user intent, a tool subset, and a TTL across every A-to-B-to-C hop. Scope is monotonically narrowing and the intent digest is immutable along the chain. |"
new_asi03 = "| **ASI03** | Identity Abuse | Signed delegation tokens bind the original user intent, a tool subset, and a TTL across every A-to-B-to-C hop. Scope is monotonically narrowing and the intent digest is immutable along the chain. |"
txt = txt.replace(old_asi03, new_asi03)

# 2. Test count
txt = txt.replace("193/193 tests passing", "193/193 tests passing")

# 3. Delegation section
delegation_doc = """## Delegation (inter-agent trust)

An allow-list answers *"may this agent call this tool?"*. It cannot answer *"is this agent acting on a request a user actually made?"* — and that gap is where **ASI03 (Agent Identity & Privilege Abuse)** lives:

> A low-privilege support agent forwards a "request" to a high-privilege finance agent. The finance agent trusts the internal call and issues a refund without ever re-checking what the original user asked for. No individual permission was violated; the *authority* was laundered across the hop.

AgentBrake issues **signed delegation tokens**. A token cryptographically binds the delegator, the delegatee, a digest of the original user intent, the delegated tool subset, and an expiry — signed under a dedicated domain so a token signature can never be replayed as a receipt signature, or the reverse.

```python
from agentbrake import delegation

token = delegation.grant(
    delegator="support-agent",
    delegatee="finance-agent",
    intent="Refund order #4521 for jane@corp.com",
    tools=["lookup_order", "issue_refund"],
    ttl_seconds=300,
)

with agentbrake.run(delegation=token) as r:
    dispatch("issue_refund", {...})     # in scope
    dispatch("send_email", {...})       # AgentBrakeInterrupt(DELEGATION) + signed receipt
```

Sub-delegation chains (A to B to C) are first-class. Each hop is verified on issue **and** on acceptance, so a token forged outside this code is rejected the same way:

```python
sub = delegation.grant(
    delegator="finance-agent",
    delegatee="payment-bot",
    tools=["issue_refund"],          # must be a subset of the parent - ValueError otherwise
    parent=token,                     # inherits the original intent digest
    ttl_seconds=60,
)
```

Four invariants hold across a chain: every signature verifies; each hop's delegatee is the next hop's delegator; **scope only narrows** (`tools[i+1]` is a subset of `tools[i]`); and the **intent digest is identical at every hop** — the original request cannot be rewritten in transit. Effective expiry is the minimum across the chain, and the TTL is re-checked on every call, not just at acceptance.

Every grant, acceptance, and block mints a signed receipt into the same hash-chained ledger as [flow blocks](#flow-control-taint-tracking) — same export bundle, same `agentbrake verify` CLI. Verification is *deep*: the verifier re-checks the signature of the token embedded in each receipt, not just the receipt itself.

### Limitations (read these)

- **Identity binding requires pinning.** Without a pinned directory, a token proves *"signed by the holder of key X, who claims to be `support-agent`"* — not that the key belongs to that agent. Pass `trusted_agents={"support-agent": pub_hex}` to `delegation.verify()` to bind identities to keys; only then is impersonation ruled out.
- **The user's intent is attested by the root agent, not signed by the user.** The token freezes what the root agent declared. A compromised root agent can declare a false intent. Client-signed intent is future work.
- **Scope is tool names, not arguments.** "May refund up to EUR 100" is not expressible yet — only "may call `issue_refund`".
- **TTLs run on the local clock**, self-reported like every other timestamp in AgentBrake.
- **Same-process key exposure applies**, exactly as documented for local-mode receipts.

"""

marker = "## Delegation (inter-agent trust)

An allow-list answers *"may this agent call this tool?"*. It cannot answer *"is this agent acting on a request a user actually made?"* — and that gap is where **ASI03 (Agent Identity & Privilege Abuse)** lives:

> A low-privilege support agent forwards a "request" to a high-privilege finance agent. The finance agent trusts the internal call and issues a refund without ever re-checking what the original user asked for. No individual permission was violated; the *authority* was laundered across the hop.

AgentBrake issues **signed delegation tokens**. A token cryptographically binds the delegator, the delegatee, a digest of the original user intent, the delegated tool subset, and an expiry — signed under a dedicated domain so a token signature can never be replayed as a receipt signature, or the reverse.

```python
from agentbrake import delegation

token = delegation.grant(
    delegator="support-agent",
    delegatee="finance-agent",
    intent="Refund order #4521 for jane@corp.com",
    tools=["lookup_order", "issue_refund"],
    ttl_seconds=300,
)

with agentbrake.run(delegation=token) as r:
    dispatch("issue_refund", {...})     # in scope
    dispatch("send_email", {...})       # AgentBrakeInterrupt(DELEGATION) + signed receipt
```

Sub-delegation chains (A to B to C) are first-class. Each hop is verified on issue **and** on acceptance, so a token forged outside this code is rejected the same way:

```python
sub = delegation.grant(
    delegator="finance-agent",
    delegatee="payment-bot",
    tools=["issue_refund"],          # must be a subset of the parent - ValueError otherwise
    parent=token,                     # inherits the original intent digest
    ttl_seconds=60,
)
```

Four invariants hold across a chain: every signature verifies; each hop's delegatee is the next hop's delegator; **scope only narrows** (`tools[i+1]` is a subset of `tools[i]`); and the **intent digest is identical at every hop** — the original request cannot be rewritten in transit. Effective expiry is the minimum across the chain, and the TTL is re-checked on every call, not just at acceptance.

Every grant, acceptance, and block mints a signed receipt into the same hash-chained ledger as [flow blocks](#flow-control-taint-tracking) — same export bundle, same `agentbrake verify` CLI. Verification is *deep*: the verifier re-checks the signature of the token embedded in each receipt, not just the receipt itself.

### Limitations (read these)

- **Identity binding requires pinning.** Without a pinned directory, a token proves *"signed by the holder of key X, who claims to be `support-agent`"* — not that the key belongs to that agent. Pass `trusted_agents={"support-agent": pub_hex}` to `delegation.verify()` to bind identities to keys; only then is impersonation ruled out.
- **The user's intent is attested by the root agent, not signed by the user.** The token freezes what the root agent declared. A compromised root agent can declare a false intent. Client-signed intent is future work.
- **Scope is tool names, not arguments.** "May refund up to EUR 100" is not expressible yet — only "may call `issue_refund`".
- **TTLs run on the local clock**, self-reported like every other timestamp in AgentBrake.
- **Same-process key exposure applies**, exactly as documented for local-mode receipts.

## Security coverage"
i = txt.find(marker)
if i != -1:
    txt = txt[:i] + delegation_doc + txt[i:]

with open("README.md", "w", encoding="utf-8") as f:
    f.write(txt)

checks = []
if new_asi03 in txt: checks.append("ASI03 updated")
if "193/193" in txt: checks.append("test count updated")
if "## Delegation" in txt: checks.append("delegation section added")
print("OK -", ", ".join(checks))e       | Observability + caching        | After                    | Yes (open core) |
| AgentOps       | Observability + replay         | After                    | No (cloud)      |

We don't compete with these — we complement them. Run AgentBrake as your last line of defense before the tool actually executes.

## Security coverage - OWASP Top 10 for Agentic Applications (2026)

AgentBrake maps to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) - the peer-reviewed risk taxonomy security teams now use to evaluate agent deployments. Every enforcement decision AgentBrake makes produces an **Ed25519-signed, hash-chained receipt** that a third party (an auditor, a client's security team) can verify **offline with only the public key** - no trust in the AgentBrake server required.

| OWASP | Risk | AgentBrake |
|-------|------|------------|
| **ASI02** | Tool Misuse | Tool allow-list + loop / retry-storm detection stop recursive tool abuse. |
| **ASI01** | Agent Goal Hijack | Flow-control engine (taint tracking) blocks injection to exfiltration. |
| **ASI08** | Cascading Failures | Circuit-breaker halt-and-escalate before a failure snowballs. |
| **ASI10** | Rogue Agents | Verifiable audit trail for post-incident forensics. |
| **ASI03** | Identity Abuse | Signed delegation tokens bind the original user intent, a tool subset, and a TTL across every A-to-B-to-C hop. Scope is monotonically narrowing and the intent digest is immutable along the chain. |
| **ASI06** | Memory Poisoning | Roadmap - signed memory entries. |

**Not in scope (by design):** AgentBrake enforces *actions*, not *content*. Use it alongside text-filtering guardrails.

### Why this matters now

- **EU AI Act high-risk obligations live since August 2, 2026.** Penalties up to 7% of global turnover.
- **OWASP published a dedicated Top 10 for Agentic Applications** (Dec 2025).
- **Auditors want evidence.** AgentBrake produces that record and makes it independently verifiable.

---

Built by [BOSSMETALIQUE](https://github.com/BOSSMETALIQUE). MIT License. Feedback welcome on GitHub Issues.
