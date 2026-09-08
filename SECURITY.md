# Security Policy

AgentBrake's whole purpose is stopping unsafe agent behavior and producing verifiable proof of
enforcement decisions. A vulnerability here is not a routine bug — treat it accordingly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.** Use
[GitHub Security Advisories](https://github.com/BOSSMETALIQUE/agentbrake/security/advisories/new)
("Report a vulnerability" on the repo's Security tab) for a private disclosure channel.

Include, as available:
- AgentBrake version (or commit SHA) and Python version.
- Which surface is affected: a detector (loop/budget/escalation/flow/delegation), the FastAPI
  backend, the receipt/signing/Merkle chain, or the CLI.
- A minimal reproduction and the impact you believe it has (e.g. "a crafted delegation token bypasses
  scope narrowing" or "the flow detector can be made to miss a tainted call").

We aim to acknowledge a report within 5 business days.

## Supported versions

AgentBrake is pre-1.0 and moves fast. Only the latest published release on PyPI receives security
fixes; there is no long-term-support branch yet. Upgrade before reporting if you can.

## Scope

In scope:
- Bypasses of any detector (loop, retry-storm, budget, escalation, flow, delegation).
- Forgeable or tamperable receipts/attestations, hash-chain or Merkle-proof weaknesses.
- Delegation token issues: scope widening across a chain, intent-digest mismatches, expired tokens
  accepted, signature verification bypasses.
- Authentication bypass on the remote-mode backend (SDK vs. approver secret separation).
- Anything that lets a guarded agent process observe or exercise the approver secret.

Out of scope (already documented, not a vulnerability):
- The [documented limits](README.md#what-a-receipt-proves--and-what-it-doesnt) of what a receipt
  proves — e.g. a compromised process can read its own in-memory signing key, timestamps are
  self-reported, or the key holder can rewrite history before an export is anchored externally.
- Content-level attacks (jailbreaks, toxic output) — AgentBrake enforces actions, not text; see
  [Security coverage](README.md#security-coverage---owasp-top-10-for-agentic-applications-2026).
- Denial of service from a misconfigured or self-inflicted setup (e.g. an intentionally huge
  `budget_usd`).

## Disclosure

We follow coordinated disclosure: we'll work with you on a fix and a release before any public
write-up, and credit the reporter (unless you'd rather stay anonymous).
