# Examples

Runnable demos of every AgentBrake detector and workflow. Each script is
self-describing — read the module docstring at the top of the file for full
detail; this table is the index.

| File | Demonstrates | Prerequisites | Run |
|---|---|---|---|
| [`00_config_snippet.py`](00_config_snippet.py) | Minimal `agentbrake.init()` config (not runnable standalone — used in the demo video intro) | — | — |
| [`01_loop_detection.py`](01_loop_detection.py) | `LoopDetector` trips on 3 consecutive identical tool calls | `ANTHROPIC_API_KEY` in `.env`, LangGraph deps (`pip install -r requirements.txt`) | `python examples/01_loop_detection.py` |
| [`02_budget_runaway.py`](02_budget_runaway.py) | `BudgetDetector` trips on cumulative cost overrun | Same as above | `python examples/02_budget_runaway.py` |
| [`03_privilege_escalation.py`](03_privilege_escalation.py) | `EscalationDetector` blocks a tool outside the allowlist | Same as above | `python examples/03_privilege_escalation.py` |
| [`04_remote_validation.py`](04_remote_validation.py) | Remote mode: human-in-the-loop approve/kill via the FastAPI backend | Same as above, plus a running backend (`uvicorn agentbrake.server.main:app --port 8000`) and `AGENTBRAKE_SDK_SECRET` set in both processes | `python examples/04_remote_validation.py` |
| [`05_prompt_injection_exfiltration.py`](05_prompt_injection_exfiltration.py) | Flow control (taint tracking) stops a prompt-injection → exfiltration attack | None — self-contained, no API key, no server | `python examples/05_prompt_injection_exfiltration.py` |
| [`06_verifiable_audit_trail.py`](06_verifiable_audit_trail.py) | Full pipeline: attack → block → signed receipts → export → offline verify → tamper detection → compliance report | None — self-contained, no API key, no server | `python examples/06_verifiable_audit_trail.py` |
| [`07_cometapi_cost_tracking.py`](07_cometapi_cost_tracking.py) | Real token-based LLM cost tracking via the CometAPI provider, wired into `BudgetDetector` | `COMETAPI_KEY` in `.env` ([get one](https://www.cometapi.com)), `pip install py-agentbrake[cometapi]` | `python examples/07_cometapi_cost_tracking.py` |
| [`demo_auto.py`](demo_auto.py) | Unattended end-to-end run of demos 01–04 (local breakers + remote auto-approve), used for screen recordings | Same as 01–04 | `python examples/demo_auto.py` |

`_shared.py` holds helpers common to the LangGraph-based demos (env loading, agent scaffolding, output formatting) — not runnable on its own.

See the main [README](../README.md) for the concepts each demo exercises, and [`docs/api-reference.md`](../docs/api-reference.md) for the full public API.
