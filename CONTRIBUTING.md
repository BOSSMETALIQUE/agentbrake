# Contributing to AgentBrake

Thanks for considering a contribution. AgentBrake is a small project with a focused scope, so a few minutes of alignment saves both of us time.

## What we're building

A circuit breaker for LLM agents in production. The core idea is **enforcement, not observability** — we interrupt agents mid-run, we don't just log what happened after. Keep this in mind when proposing features.

## What's in scope

- New detectors (e.g. semantic loops via embeddings, cost spikes, suspicious arg patterns)
- New integrations (frameworks beyond LangGraph: CrewAI, Autogen, AG2, raw OpenAI SDK)
- Improvements to the validation UI (better context display, keyboard shortcuts)
- Performance: making the SDK fast enough to add zero noticeable latency
- Better test coverage

## What's out of scope (for now)

- Replacing existing observability tools (LangSmith, Helicone, etc.) — we complement them
- Authentication / multi-tenancy for the backend — local-first for now
- Cloud-hosted version — open source SDK only

## Development setup

Requirements : Python 3.9+, git.

```bash
git clone https://github.com/BOSSMETALIQUE/agentbrake.git
cd agentbrake
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate    # Windows
pip install -e ".[dev]"
pytest
```

If `pytest` returns 15 passed, you're good to go.

## Running the examples (optional)

The examples in `examples/` use LangGraph + Anthropic API. They require an Anthropic API key and additional dependencies.

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env to add your ANTHROPIC_API_KEY
python examples/01_loop_detection.py
```

## Code style

- Type hints on all public functions
- Docstrings concise — no novels, just intent and tricky bits
- Format with `ruff` or `black`, your call (no enforcement yet)
- Tests next to the code they cover, not in a parallel hierarchy

## Pull requests

1. Open an issue first if your change is bigger than a typo. Saves everyone time if the direction is wrong.
2. Branch from `main`, name it `feat/short-description` or `fix/short-description`.
3. Run `pytest` locally before pushing. CI will catch regressions but local feedback is faster.
4. Keep PRs focused. One concern per PR. A PR that "also fixes" three unrelated things is harder to review than three small PRs.
5. Reference the issue in the PR description if there is one.

## Reporting issues

Use the issue templates (Bug report / Feature request) if available. Otherwise, include:
- Python version, OS, AgentBrake version (or commit SHA)
- Minimum reproducible snippet
- What you expected vs what happened

## Questions?

Open a GitHub Discussion (preferred) or an issue with the `question` label. Email isn't great for this project — public Q&A helps the next person hitting the same wall.
