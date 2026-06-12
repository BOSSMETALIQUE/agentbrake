---
title: "I built a circuit breaker for LLM agents after seeing someone lose $200 overnight"
published: false
tags: ai, python, llm, opensource
---

A few weeks ago I was lurking in the LangChain Slack instead of doing my actual coursework, and two messages stuck with me.

The first one: someone got billed for **211 looping runs on their very first question**. Not their hundredth. Their first. The agent just kept going.

The second one: a dev lost **800 yuan** (around $110) because LangChain's default recursion limit is `9999`. Nobody sets that on purpose. It's just the default, and the default is "basically infinite."

I'm a student. $110 is a lot of money to me. The idea that an agent could quietly burn that overnight, while you're asleep, because of a malformed tool response and a default value nobody read — that genuinely freaked me out. So I built a thing. This is the story of that thing.

## The problem: agents have a gas pedal but no brake

Here's what nobody tells you when you ship your first agent.

You wire up LangGraph, you give the model a `tools` array, you write a nice prompt, and it works in the demo. Great. Then it goes to production and one of three things eventually happens:

1. **It loops.** A tool returns garbage, the model decides to retry, gets the same garbage, retries again... forever. Or until your budget is gone.
2. **It overspends.** Nothing is "broken," it's just doing a lot of work, and the bill quietly climbs past anything reasonable.
3. **It does something it shouldn't.** A user prompt-injects your support bot and suddenly it's calling `delete_database` because, well, that function was in the tools list and nobody said it couldn't.

And here's the part that bugged me the most: **we already have tools for this, except they all watch instead of act.**

LangSmith, Langfuse, Helicone, AgentOps — they're great. I use them. But they're *observability*. They show you, in a beautiful dashboard, that your agent looped 211 times. **After it already did.** The dashboard is a security camera. It records the break-in. It doesn't lock the door.

I kept thinking: where's the brake pedal? The thing that stops the agent *during* the run, before the damage, not the report you read the morning after?

I couldn't find one I liked. So I wrote one.

## What I built: AgentBrake

AgentBrake is a Python decorator that sits in front of your tool calls. Every single tool call your agent tries to make passes through it first, and it checks three things before letting the call execute:

- **Loop** — are you calling the same tool with the same arguments over and over?
- **Budget** — would this call push you past the dollar ceiling you set?
- **Escalation** — is this tool even on the allowed list?

If any check trips, it raises an exception *instead of running the tool*. The agent stops. Mid-run. Before the money is spent or the database is dropped.

That's the whole pitch. It's a circuit breaker. When things go wrong, it pops, and nothing downstream of it gets power.

## How it works (it's genuinely 3 lines)

You configure it once:

```python
import agentbrake

agentbrake.init(
    allowed_tools=["search", "read_file"],
    budget_usd=5.0,
)
```

Then you put the decorator on whatever function dispatches your tools:

```python
@agentbrake.guard()
def call_tool(name: str, args: dict):
    return my_tools[name](**args)
```

That's it. That's the integration. If the agent loops, blows the $5 budget, or tries to call something outside `allowed_tools`, `call_tool` raises `AgentBrakeInterrupt` instead of executing the tool.

You catch it wherever you run the agent:

```python
from agentbrake import AgentBrakeInterrupt

try:
    agent.run("summarize my inbox")
except AgentBrakeInterrupt as e:
    print(f"Stopped: {e.reason}")  # LOOP, BUDGET, or ESCALATION
```

Under the hood, the decorator keeps a little `RunState` in memory — the run ID, the running cost, and the full history of calls. Every call runs through the three detectors in order (escalation → loop → budget), and the first one that fires raises before your tool ever runs.

Let me explain each detector, because they're simpler than you'd think.

**Escalation** is a one-liner. Is the tool name in the allow-list? No? Stop. This is the cheapest and most decisive check, so it goes first. I don't care if you're under budget — if you're trying to call `delete_database` and it's not on the list, that's a hard no.

**Budget** projects the cost *before* the call. It takes the running total, adds what this next call would cost, and if that *projected* number is over your ceiling, it trips. The key word is projected — it stops you before you cross the line, not after.

**Loop** is the one I'm most proud of, so it gets its own section.

## The thing I'm proudest of: structural hashing for loops

My first instinct for loop detection was the obvious one: compare the tool name and arguments as strings. If the last 3 calls are identical strings, it's a loop.

That's fragile. `{"q": "weather", "lang": "en"}` and `{"lang": "en", "q": "weather"}` are the *same call*, but as strings they're different. A model that shuffles its argument order — and they do — would slip right past a naive string check.

So instead, each call gets a **structural hash**:

```python
def _structural_hash(call):
    payload = json.dumps(
        {"name": call.name, "args": call.args},
        sort_keys=True,   # key order can't fool it
        default=str,      # non-JSON values still hash
    )
    return hashlib.sha256(payload.encode()).hexdigest()
```

`sort_keys=True` is the whole trick. It normalizes the argument dict before hashing, so `{a, b}` and `{b, a}` produce the exact same hash. `default=str` is the safety net — if an argument isn't JSON-serializable, it gets stringified instead of crashing the detector. The last thing you want is your *safety mechanism* throwing an unhandled error.

Then loop detection is just: hash the new call, compare it to the last two. Three identical structural hashes in a row → it's a loop → stop. The agent in my demo gets a fake "transient error, please retry the exact same query" response, dutifully retries... and gets caught on the third attempt.

## The demo

I recorded a short walkthrough showing all three detectors tripping on a real LangGraph agent — the loop, the runaway budget, and the privilege escalation:

📺 **https://youtu.be/uHbjP2SGMsI**

Watching an agent get *stopped* mid-loop is way more satisfying than I expected.

## What I actually learned building this

This is the part I'd tell a friend over coffee, because some of it surprised me.

**1. The framework actively fights you.** This was the big one. My detectors worked perfectly in isolation, then I plugged them into a real LangGraph agent and... nothing stopped. Turns out LangGraph's `ToolNode` *swallows tool exceptions by default* and feeds them back to the model as an observation. So my breaker would fire, raise its exception, and the framework would catch it, hand the model a polite "tool failed, want to retry?", and the model would just... keep going. My safety mechanism became another thing for the loop to loop over. The fix was one argument:

```python
# Default behavior eats your exception and tells the model to retry.
# The breaker only works if the exception is allowed to propagate.
tool_node = ToolNode(tools, handle_tool_errors=False)
```

I would never have guessed that. A circuit breaker is useless if the wiring around it catches the spark.

**2. "Before" vs "after" is the entire product.** It would have been so easy to build yet another dashboard. The hard, interesting constraint was: every check has to happen *before* the tool runs. That's why the budget detector projects the cost instead of summing it afterward, and why the whole thing is a decorator that intercepts the call rather than a logger that records it. The moment you let the call run first, you've rebuilt observability.

**3. Fail closed, always.** I added an optional remote mode where a human can approve or kill a flagged run from a browser. The obvious question: what if that backend is unreachable? My first version just... let the call through, because erroring felt user-hostile. Then I realized that's exactly backwards. A brake that releases when it loses power isn't a brake. So now, if the validation server is down, it stops the run. A safety device that fails open is worse than no safety device, because you *think* you're protected.

**4. Sync over async, on purpose.** I wanted to use `async` everywhere because it feels more "real." But `@guard()` wraps an arbitrary user function that might be totally synchronous, and forcing someone to bolt on an event loop just so my breaker can pause for human review would be a horrible developer experience. Sometimes the boring choice is the correct one.

## It's early, and I'd love your eyes on it

Honest status: this is **v0.0.1**. Local mode is solid (15/15 tests passing), the LangGraph examples and the remote validation UI work end to end. The cost model is currently a flat per-call estimate rather than real token accounting — that's the next thing on my list. I'm putting it out there because I want real users to tell me where the API feels wrong before I lock it in.

If you've ever had an agent do something dumb and expensive, I'd genuinely love your feedback.

```bash
# coming soon:
pip install agentbrake

# works today:
pip install git+https://github.com/BOSSMETALIQUE/agentbrake.git
```

- **GitHub:** https://github.com/BOSSMETALIQUE/agentbrake
- **Landing page:** https://bossmetalique.github.io/agentbrake/

Keep your dashboards. Just add a brake pedal too.

Thanks for reading. 🛑
