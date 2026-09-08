# Changelog

All notable changes to AgentBrake are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.2.0...v0.2.2
[0.2.0]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/BOSSMETALIQUE/agentbrake/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/BOSSMETALIQUE/agentbrake/releases/tag/v0.1.0
