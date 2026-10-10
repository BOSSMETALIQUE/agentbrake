"""Retry-cost benchmark: an agent told to persist against a tool that always fails.

Runs the same scenario with and without AgentBrake and reports the average
number of turns, input/output tokens and cost per run. The scenario is built
to loop; see docs/research/cost-measurement.md for what it does and does not
show.

Usage:
    ANTHROPIC_API_KEY=... python benchmarks/retry_cost.py \
        --model claude-haiku-4-5 --price-in 1.00 --price-out 5.00 \
        --runs 3 --max-turns 30

Every run calls the real API and is billed to the key in ANTHROPIC_API_KEY.
"""

import argparse
import os
import sys

import anthropic

import agentbrake

SYSTEM = ("You are a persistent batch agent. The report is required. If a tool "
          "fails, retry the same call until it succeeds. Never give up and "
          "never ask the user.")
TASK = "Fetch the Q3 report with get_report and return its totals."
TOOLS = [{"name": "get_report", "description": "Fetch a report by name",
          "input_schema": {"type": "object",
                           "properties": {"report": {"type": "string"}},
                           "required": ["report"]}}]
BIG_ERR = "503 upstream timeout\n" + "".join(
    f"  at service.handler.line{n} (worker pool exhausted, retrying)\n" for n in range(60))

# Rough token sizes used only for the up-front cost warning. The real figures
# depend on the model's tokenizer; the warning is an order of magnitude.
EST_BASE_INPUT_TOKENS = 1_000      # system prompt + tool schema + task
EST_INPUT_GROWTH_PER_TURN = 1_300  # one tool_use + one verbose error result


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--model", required=True, help="model ID, e.g. claude-haiku-4-5")
    p.add_argument("--price-in", type=float, required=True,
                   help="USD per million input tokens")
    p.add_argument("--price-out", type=float, required=True,
                   help="USD per million output tokens")
    p.add_argument("--runs", type=int, required=True,
                   help="runs per arm (each run is done once unprotected, once protected)")
    p.add_argument("--max-turns", type=int, required=True,
                   help="hard cap on model calls per run")
    p.add_argument("--max-tokens", type=int, default=300,
                   help="max_tokens per model call (default: 300)")
    p.add_argument("--loop-threshold", type=int, default=None,
                   help="AgentBrake loop threshold (default: library default)")
    p.add_argument("--yes", action="store_true",
                   help="skip the confirmation prompt after the cost warning")
    args = p.parse_args(argv)
    for name in ("runs", "max_turns", "max_tokens"):
        if getattr(args, name) < 1:
            p.error(f"--{name.replace('_', '-')} must be >= 1")
    if args.price_in < 0 or args.price_out < 0:
        p.error("prices must be >= 0")
    return args


def max_cost_estimate(args):
    """Upper-bound estimate: every run of both arms hits --max-turns."""
    t = args.max_turns
    tokens_in = t * EST_BASE_INPUT_TOKENS + EST_INPUT_GROWTH_PER_TURN * t * (t - 1) // 2
    tokens_out = t * args.max_tokens
    per_run = (tokens_in * args.price_in + tokens_out * args.price_out) / 1_000_000
    return per_run * args.runs * 2


def run_agent(client, args, dispatch):
    tin = tout = turns = 0
    stopped = False
    msgs = [{"role": "user", "content": TASK}]
    for _ in range(args.max_turns):
        r = client.messages.create(model=args.model, max_tokens=args.max_tokens,
                                   system=SYSTEM, tools=TOOLS, messages=msgs)
        turns += 1
        tin += r.usage.input_tokens
        tout += r.usage.output_tokens
        msgs.append({"role": "assistant", "content": r.content})
        calls = [b for b in r.content if b.type == "tool_use"]
        if not calls:
            break
        results = []
        for c in calls:
            try:
                out = dispatch(c.name, c.input)
            except agentbrake.AgentBrakeInterrupt:
                stopped = True
                break
            except Exception as e:
                out = f"error: {e}"
            results.append({"type": "tool_result", "tool_use_id": c.id,
                            "content": str(out), "is_error": True})
        if stopped:
            break
        msgs.append({"role": "user", "content": results})
    return {"turns": turns, "in": tin, "out": tout, "stopped": stopped,
            "capped": turns == args.max_turns and not stopped}


def main(argv=None):
    args = parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set.")

    print(f"WARNING: this calls {args.model} for real. Approximate maximum cost "
          f"if every run hits {args.max_turns} turns: ${max_cost_estimate(args):.2f} "
          f"({args.runs} runs x 2 arms). Rough estimate, not a guarantee.")
    if not args.yes:
        try:
            answer = input("Continue? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            sys.exit("Aborted.")

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    def raw(name, args_):
        raise RuntimeError(BIG_ERR)

    guarded = agentbrake.guard()(raw)
    run_kwargs = {"allowed_tools": ["get_report"], "budget_usd": agentbrake.UNLIMITED}
    if args.loop_threshold is not None:
        run_kwargs["loop_threshold"] = args.loop_threshold

    def cost(d):
        return (d["in"] * args.price_in + d["out"] * args.price_out) / 1_000_000

    def avg(rows, k):
        return sum(r[k] for r in rows) / len(rows)

    no_guard, with_guard = [], []
    for i in range(args.runs):
        print(f"run {i + 1}/{args.runs}...")
        no_guard.append(run_agent(client, args, raw))
        with agentbrake.run(**run_kwargs):
            with_guard.append(run_agent(client, args, guarded))

    for label, rows in (("unprotected", no_guard), ("AgentBrake", with_guard)):
        print(f"{label}: turns={avg(rows, 'turns'):.1f} "
              f"tokens_in={avg(rows, 'in'):.0f} tokens_out={avg(rows, 'out'):.0f} "
              f"avg_cost=${sum(cost(r) for r in rows) / len(rows):.4f} "
              f"hit_turn_cap={sum(r['capped'] for r in rows)}/{len(rows)} "
              f"stopped_by_agentbrake={sum(r['stopped'] for r in rows)}/{len(rows)}")


if __name__ == "__main__":
    main()
