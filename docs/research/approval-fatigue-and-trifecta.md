# Research: the lethal trifecta and approval fatigue

Background for the AgentBrake v0.4 Claude Code hook. The goal of v0.4 is to ask
the user for confirmation **rarely**, and only with a good reason, because a
confirmation approved by reflex protects no one. This note records what the
sources actually say; every figure below was read on its primary source unless
marked "secondhand".

Sources are listed inline and collected at the end. Dates are as published.

## 1. The "lethal trifecta"

Simon Willison, *The lethal trifecta for AI agents: private data, untrusted
content, and external communication* (16 June 2025). Read in full.

The three capabilities, in his words:

1. **Access to your private data** — "one of the most common purposes of tools
   in the first place!"
2. **Exposure to untrusted content** — "any mechanism by which text (or images)
   controlled by a malicious attacker could become available to your LLM".
3. **The ability to externally communicate** "in a way that could be used to
   steal your data" (he calls it exfiltration).

His core claim: an agent that has all three at once can be turned against its
user, because an LLM follows instructions found in the content it reads and
cannot reliably tell them apart from instructions from its operator. The
recommended mitigation is blunt: **"The only way to stay safe there is to avoid
that lethal trifecta combination entirely."**

On guardrail products that claim to catch attacks: he argues a detector that
stops, say, 95% of attacks is "very much a failing grade" in security, because
an adversary just iterates until they find the 5% that gets through. And on MCP
specifically: it "encourages users to mix and match tools from different sources
that can do different things", and once a user mixes tools themselves, a vendor
cannot protect them.

**What this means for our design.** The trifecta is a *conjunction*. Any single
leg is survivable; the danger is all three together. A guard that blocks on a
single leg (every web fetch, every outbound command) produces mostly false
alarms — exactly the thing that causes the fatigue described below. v0.4's
default mode acts on the conjunction: it only hard-denies when private data
**and** untrusted content **and** an unlisted external destination coincide.

## 2. Approval fatigue

### 2.1 The oldest hard evidence: browser warnings

Akhawe & Felt, *Alice in Warningland: A Large-Scale Field Study of Browser
Security Warning Effectiveness*, USENIX Security 2013. Read the PDF
(`pdftotext`), including §5, §7.4 and §7.5.

- Telemetry over **25,405,944 warning impressions** in Chrome and Firefox.
- Clickthrough (bypass) rates: malware/phishing warnings 9–23%; Firefox SSL
  warnings **33.0%**; Chrome's SSL warning **70.2%** — "the user experience of a
  warning can have a significant impact on user behavior."
- §7.5 "Warning Fatigue": "In Google Chrome, users click through the most common
  SSL error faster and more frequently than other errors." They cite work
  modelling "user attention to security warnings as a finite resource" and
  conclude: "security practitioners should limit the number of warnings that
  users encounter."

The lesson is 12 years old and directly applicable: attention is finite, and
every needless prompt spends some of it. A guard that prompts often trains the
user to click through.

### 2.2 Anthropic's own numbers on Claude Code

Anthropic, *Making auto mode the default in Claude Code* (claude.com blog,
7 August 2026). Read in full.

- **"users approve 97% of permission prompts in Claude Code."** Anthropic ties
  this to approval fatigue: "Over time that leads to approval fatigue, where
  people stop paying close attention to what they're approving." (The earlier
  engineering post, *Claude Code auto mode*, 25 March 2026, gave 93%; the 97%
  is the newer figure.)
- A controlled study with **1,053 paid testers**: partway through a session one
  permission prompt was swapped for a clearly dangerous command. **Human review
  caught 13.6%** of the dangerous commands (143/1,053); **auto mode caught 89%**
  (937/1,053). Anthropic notes testers knew they were evaluated and nothing
  dangerous actually ran.
- Decline within a session: humans blocked ~17% of dangerous commands early,
  falling to ~5% "after 50 or more prior prompts"; the classifier stayed flat.
- Production data (flagged sessions, May–June 2026): a harmful unrequested
  action appeared in **6.3%** of manually-approved sessions vs **2.4%** of auto
  mode sessions (severity 7+).
- Anthropic's caveats, quoted: auto mode "relies on classification systems and
  therefore does not eliminate risk"; they still recommend reviewing "high-stakes
  changes to production infrastructure" yourself; the 7% miss figure from Apollo
  Research red-teaming is on "synthetic, adversarial attacks" and "should not be
  taken as the miss rate on real traffic".

The 97% / 13.6% pairing is the single most important input to this work: when a
tool asks constantly, people approve almost everything, and their review adds
almost nothing. The answer is to ask less, not to ask more loudly.

### 2.3 A game, not a study

Alex Wauters, *Suffering from Agent Permission Fatigue?* (scalex.dev,
5 August 2026, update 10 August). Read in full. A browser game where you play
the human-in-the-loop.

- "over 40,000 runs and 409,000 individual approve/deny decisions."
- "The average player missed **1 in 3 threats** (mean accuracy 66.3%)";
  "**32.9%** of sessions ended with a negative score"; for one planted command,
  "Two thirds of players approved it anyway."
- The author's own caveat, quoted: "While it's just a game and not an academic
  study" — and ~34% of the commands shown were threats, far above real life.

Treat it as suggestive, not rigorous. It points the same way as the other two.

### 2.4 A figure we are NOT citing

Several posts quote "93% of permission prompts are approved" attributed only to
"Claude Code telemetry" with no link; one blog calls it unsourced "folklore".
We cite the 97% and 93% figures only because they appear in Anthropic's own
posts (§2.2). We did not find an independent, peer-reviewed study of
coding-agent approval rates.

## 3. How other tools manage prompt frequency

### 3.1 Claude Code itself

Claude Code docs, *Configure permissions* and *Install and manage plugins*
(code.claude.com, read October 2026), plus the two Anthropic posts above.

- **Permission modes**: manual (ask per action), `acceptEdits`, `plan`,
  `auto` (a Sonnet-based classifier reviews each action instead of the user),
  `dontAsk` (auto-deny anything that would prompt), `bypassPermissions`. Since
  14 August 2026 **auto mode is the default** for new Pro/Max/Team sessions.
- **Sandboxing** (*Claude Code sandboxing*, 20 Oct 2025): "In our internal
  usage, we've found that sandboxing safely reduces permission prompts by 84%."
  Network egress goes through "a unix domain socket connected to a proxy server
  running outside the sandbox" with a domain allow-list; the proxy asks before
  a new domain. Built on "Linux bubblewrap and MacOS seatbelt" — i.e. **not
  native Windows** (WSL2 only). This is the single biggest reason the AgentBrake
  hook matters on Windows: the OS-level egress control Anthropic ships does not
  run there.
- **Auto mode classifier** (*auto mode* post, 25 March 2026): a transcript
  classifier on Sonnet 4.6 that **only sees user messages and the agent's tool
  calls — never tool outputs**, which Anthropic calls its main structural
  defence against injection. A separate server-side probe scans tool outputs for
  injection and annotates them. On a block it returns a tool-result telling the
  agent to find a safer path; after **3 consecutive or 20 total** denials it
  stops and escalates to the human (in `claude -p`, it terminates). Reported
  error rates (their Table 1, full pipeline): real-traffic false-positive 0.4%,
  real "overeager" false-negative **17%** ("the honest number"), synthetic
  exfiltration false-negative 5.7%.
- **How a PreToolUse hook interacts with this** (*Configure permissions*):
  "PreToolUse hook decisions don't bypass permission rules." A `deny` rule still
  denies and an `ask` rule still prompts whatever the hook returns; a hook that
  exits 2 blocks before rules are evaluated; deny-first precedence holds. So the
  hook's `deny` is authoritative, and its `ask` forces a prompt the user sees.

### 3.2 OpenAI Codex CLI

Codex sandboxing docs (developers.openai.com → learn.chatgpt.com, read Oct 2026).

- Approval policies: `on-request` ("works inside the sandbox by default and asks
  when it needs to go beyond that boundary"), `never`. `untrusted` is now
  **retired** ("no longer support[ed] as a selectable approval policy").
- Sandbox: filesystem + network boundary; network limited to allow-listed
  hostnames unless public access is turned on. "The sandbox reduces approval
  fatigue" — routine commands inside the approved boundary don't re-prompt.
- `auto_review`: "eligible approval prompts go to a reviewer agent" instead of
  the user. Platform-native enforcement on each OS, **including Windows** (native
  Windows sandbox in PowerShell, Linux impl in WSL2).

Same philosophy as Anthropic: a sandbox boundary you approve once, plus an
optional agent reviewer, instead of per-action prompts.

### 3.3 Cursor

Cursor *Run modes* docs (cursor.com, read Oct 2026).

- **Auto-review** (default): allow-listed calls run immediately; other shell
  commands run in a sandbox when possible; the rest go to a backend classifier
  (which may read files read-only to judge intent). **Allowlist**: only your
  list runs without asking. **Run Everything**: no sandbox, no classifier.
- Sandboxed network access is governed by a `sandbox.json` domain allow-list,
  with Cursor defaults for common package managers.
- Stated limits, quoted: "Auto-review is not a security boundary"; "The
  classifier can make mistakes. It can allow a call you would have blocked, or
  block a call you would have allowed."

### 3.4 Existing Claude Code security hooks

- **karanb192/claude-code-hooks** (GitHub, read Oct 2026). Pattern guards with
  three safety levels (`critical`/`high`/`strict`, default `high`). **Defaults to
  deny; ask mode is opt-in** per level. Has a `protect-secrets` guard that
  "prevents reading, modifying, or exfiltrating sensitive files (.env, SSH keys,
  cloud creds, keystores)" over Read/Edit/Write/Bash/Grep, and a
  `subagent-spawn-cap`. It is the closest existing tool to ours: it does guard
  secret files and can ask rather than hard-block. **But** each guard fires on
  its own leg independently — reading a `.env` is blocked/asked *regardless of
  whether anything untrusted is in the session* — so it will prompt on the
  common, safe case of an agent legitimately reading `.env`. It keeps no taint
  state tying a read to a later send, and it signs nothing.
- **lasso-security/claude-hooks** (GitHub, read Oct 2026). A `PostToolUse`
  defender that scans tool *outputs* (Read, WebFetch, Bash, Grep, Task, MCP) for
  injection patterns. Quoted: **"The defender warns but does not block."** The
  content still reaches Claude. No state, no proof, by design observational.
- **Superagent** (docs.superagent.sh). Uses the `UserPromptSubmit` hook to
  block prompt injections via a guard CLI (local model or API). Could not
  re-verify the Claude Code specifics: the hook docs URL now 308-redirects to a
  generic `/docs` that no longer mentions Claude Code. Treat as **unverified**.
- **Enkrypt AI** (enkryptai/secure-mcp-gateway, only reachable via a Glama
  mirror; github.com README returned 404 and the docs 404). Mirror says its
  PreToolUse hook can "allow, deny, or ask" using the Enkrypt API for
  prompt-injection/PII/toxicity. Treat as **unverified** (could not reach a
  primary source; "11 events" claim is internally inconsistent in the mirror).

### 3.5 Where AgentBrake's v0.4 hook differs

None of the tools above combines all four of: (a) **stateful taint across the
session** that ties a private read and an untrusted read to a later outbound
call; (b) a **conjunction rule** that stays silent on a single leg and only
hard-denies the full trifecta into an unlisted destination; (c) **signed,
chained receipts** of every decision, verifiable offline; (d) a **local
`stats` command** that measures the user's own click-through behaviour to expose
reflexive approval. karanb192 guards secret files but on a single leg with no
taint and no proof; lasso only warns; Superagent/Enkrypt call out to a model or
API and keep no verifiable local trail. AgentBrake decides locally, in-process,
with no network call, and signs the result.

The honest limits (carried into the README and the design docs): the Bash
analysis is a **text heuristic** over the command string, not a sandbox; the
secret-in-arguments check is **pattern matching**, not a guarantee; and the hook
is **fail-open on its own timeout** and if removed from settings. These are the
same class of limit Anthropic ("does not eliminate risk") and Cursor ("not a
security boundary") state about their own classifiers.

## Sources

- Simon Willison, *The lethal trifecta for AI agents* (2025-06-16):
  https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- Akhawe & Felt, *Alice in Warningland*, USENIX Security 2013:
  https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe
  (PDF: https://research.google.com/pubs/archive/41323.pdf)
- Anthropic, *Making auto mode the default in Claude Code* (2026-08-07):
  https://claude.com/blog/auto-mode-default-in-claude-code
- Anthropic, *Claude Code auto mode* (2026-03-25):
  https://www.anthropic.com/engineering/claude-code-auto-mode
- Anthropic, *Claude Code sandboxing* (2025-10-20):
  https://www.anthropic.com/engineering/claude-code-sandboxing
- Alex Wauters, *Suffering from Agent Permission Fatigue?* (2026-08-05):
  https://scalex.dev/blog/ai-agent-permissions-stats/
- Claude Code docs, *Configure permissions*:
  https://code.claude.com/docs/en/permissions
- Claude Code docs, *Create / install plugins and marketplaces*:
  https://code.claude.com/docs/en/plugin-marketplaces
- OpenAI Codex, *Sandboxing*: https://learn.chatgpt.com/docs/sandboxing
- Cursor, *Run modes*: https://cursor.com/docs/agent/security/run-modes
- karanb192/claude-code-hooks: https://github.com/karanb192/claude-code-hooks
- lasso-security/claude-hooks: https://github.com/lasso-security/claude-hooks
- Superagent (unverified for Claude Code): https://docs.superagent.sh/
- Enkrypt AI (unverified, mirror only):
  https://glama.ai/mcp/servers/@enkryptai/secure-mcp-gateway
