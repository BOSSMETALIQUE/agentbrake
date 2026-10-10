# Retry-loop cost: a reproducible measurement

*Research notes, October 2026. Script: [`benchmarks/retry_cost.py`](../../benchmarks/retry_cost.py).*

## The question

What does it cost when an agent keeps calling a tool that keeps failing, and
how much of that does AgentBrake's loop detection save? This note gives
one deliberately unfavourable scenario, the numbers it produced and what
the numbers do not show.

## The scenario

The script runs the same agent twice per run: once with a plain tool, and
once with the tool wrapped by `agentbrake.guard()` inside
`agentbrake.run(allowed_tools=["get_report"], budget_usd=UNLIMITED)`.
The budget is off, so only loop detection can stop the protected run.

Three ingredients make it loop:

- **Persistent instruction.** The system prompt says: *"You are a persistent
  batch agent. The report is required. If a tool fails, retry the same call
  until it succeeds. Never give up and never ask the user."*
- **Verbose error.** `get_report` always raises a `503 upstream timeout`
  followed by 60 lines of fake stack trace. That text comes back as an
  `is_error` tool result, so each retry adds roughly a thousand input tokens
  and every later call re-reads all of them.
- **Turn cap.** Each run stops after `--max-turns` model calls (30 here), even
  if the model is still retrying. Without it the unprotected arm would have no
  upper bound.

The protected run ends when AgentBrake raises `AgentBrakeInterrupt` on the
identical-call streak (default `loop_threshold` = 4). The unprotected run ends
when the model stops calling the tool or when it hits the turn cap. The tool
never succeeds, so neither arm completes the task. The comparison is only
about how much each arm spends before it stops.

Cost per run = `input_tokens × price_in + output_tokens × price_out`, using
the `usage` reported by the API and the prices passed on the command line.

## Reproducing

```bash
export ANTHROPIC_API_KEY=...   # billed for real
python benchmarks/retry_cost.py --model claude-haiku-4-5 \
    --price-in 1.00 --price-out 5.00 --runs 3 --max-turns 30
```

Before any call, the script prints an approximate worst-case cost (every run
of both arms hitting `--max-turns`) and asks for confirmation (`--yes` skips
it). That worst case uses fixed per-turn token estimates and is only an order
of magnitude. Optional: `--max-tokens` (default 300), `--loop-threshold`.

## Results

Turn cap 30. Prices in USD per million tokens. Figures are per-run averages.

| Model (in / out price) | Runs | Arm | Turns | Input tokens | Cost | Notes |
|---|---|---|---|---|---|---|
| `claude-haiku-5-5` (0.10 / 0.50) | 3 | unprotected | 5.7 | 23,952 | $0.0028 | model gives up on its own |
| | | AgentBrake | 4.0 | 11,326 | $0.0013 | |
| `claude-haiku-4-5` (1.00 / 5.00) | 3 | unprotected | 30 | 552,893 | $0.562 | turn cap hit 3/3 |
| | | AgentBrake | 4.0 | 9,837 | $0.0111 | stopped 3/3 |
| `claude-sonnet-5-5` (2.00 / 10.00) | 2 | unprotected | 30 | 696,720 | $1.4081 | turn cap hit 2/2 |
| | | AgentBrake | 4.0 | 11,152 | $0.0243 | stopped 2/2 |
| `claude-opus-5-5` | — | — | — | — | — | not measured (insufficient API credit at test time) |

What this shows:

- **Haiku 4.5 and Sonnet 5.5** followed the persistence instruction until the
  turn cap. Unprotected runs cost about 50× (Haiku 4.5) and 58× (Sonnet 5.5)
  the protected ones. Input cost grows quadratically with the number of
  retries, because every call re-reads the whole history, verbose errors
  included.
- **Haiku 5.5** gave up by itself after about 6 turns despite the
  instruction, so there was little to save: about $0.0015 per run. The
  number of protected runs AgentBrake actually interrupted was not recorded.

## Limits

Read these before quoting any figure above.

- **The scenario is built to loop.** The system prompt tells the agent to
  retry until it succeeds, and the error is padded to be expensive. A
  normally prompted agent with short errors will usually spend far less
  before it stops, with or without AgentBrake. The ratios above are a
  worst case for this setup, not an expected saving.
- **Few runs.** 3 runs for the Haiku models, 2 for Sonnet 5.5, and one
  model with no runs at all. The table reports no variance and no
  confidence intervals.
- **The 30-turn cap cuts off the unprotected arm.** Where the cap was hit,
  the unprotected cost is a lower bound: without the cap those runs would
  have cost more. The ratio is therefore also a function of the cap chosen.
- **The loop threshold is fixed at the default of 4.** The protected arm's
  cost is set almost entirely by this value. A higher threshold costs more
  per stopped loop. A lower one stops sooner but risks interrupting
  legitimate retries. Other values were not measured.
- **Varied arguments are not caught: measured, AgentBrake stopped nothing.**
  The protected runs above were stopped by the loop detector, which fires
  only on consecutive identical calls (same tool, same arguments). A
  separate measurement varied the arguments instead: `get_report` with a
  `page` number that increases on every attempt, a tool that always fails,
  Haiku 4.5, 2 runs, 30-turn cap. Both arms ran all 30 turns, with about
  563,000 input tokens each, and AgentBrake recorded no stop reason. The
  script for that variant is not published yet. Why neither detector fired:
  - The loop detector compares a SHA-256 of tool name plus arguments
    (`agentbrake/detectors.py`, `_structural_hash`). A new `page` value
    gives a new hash, so the streak never starts.
  - `RetryStormDetector` does count same-tool calls whatever their arguments
    (5 calls in a window of the last 10 calls, not a time window), so it
    reaches its threshold from the fifth attempt onward. It then exempts the
    burst as "progress" whenever a numeric argument rises or falls strictly
    over at least 3 calls, the pagination signature. That check looks only
    at the arguments, not at the outcomes, so the tool failing on every
    call does not count against it. A strictly rising `page` therefore
    passes as progress on every turn.
  - The budget, the only other stop that applies here, was disabled
    (`UNLIMITED`).

  Until that changes, an agent that retries a failing tool with a strictly
  rising or falling numeric argument is not stopped by AgentBrake's default
  configuration.
- **Behaviour depends on the instruction given to the agent.** Haiku 5.5 vs
  Haiku 4.5 already shows that two models handle the same instruction
  differently. A different prompt, tool description or error message could
  change both arms.
- **No prompt caching.** The script sends no `cache_control`. With caching,
  the repeated history in the unprotected arm would be billed at a much lower
  rate, which would shrink the gap.
- **Prices are inputs, not looked up.** Costs are computed from the prices
  passed on the command line, not read from an invoice. Check them against
  current pricing before rerunning.
- **The task never succeeds in either arm.** The benchmark measures how
  much each arm spends before it stops. It says nothing about task
  completion or about false positives on retries that would have
  succeeded.
