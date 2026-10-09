# AgentBrake as a Claude Code `PreToolUse` hook

*Research notes and design, October 2026 (Claude Code 2.1.295 on the test
machine). Goal: protect every Claude Code session with AgentBrake's flow
engine, loop/retry/budget detectors and signed receipts, from a hook that
fails closed wherever the platform lets it.*

## 1. The platform, re-verified against the official docs

Checked on 2026-10-09 against <https://code.claude.com/docs/en/hooks> (plus the
pages linked below). The brief listed seven facts; all hold, with these
corrections and additions:

| Brief said | Docs say | Consequence for the design |
|---|---|---|
| stdin: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id` | Also `prompt_id`, `scratchpad_dir`, `effort`; `agent_id`/`agent_type` inside subagents; for MCP tools an `mcp_server` object (`name`, `source`, v2.1.274+). The docs advise basing trust on `source`, not on the `mcp__<server>__` prefix | Ignore unknown fields; key state on `session_id` only (subagents share their parent's taint). MCP classification is name-based in v1, see §5 |
| Exit 2 blocks, stderr to Claude | Exit 2 blocks "whether or not you print JSON: even a JSON `permissionDecision` of `"allow"` can't override it"; the reason is stderr *or* the JSON reason. Other non-zero codes: "doesn't block on its own", the transcript shows a hook error | Internal errors exit 2 |
| JSON decisions `allow`/`deny`/`ask`/`defer`, `permissionDecisionReason`, `updatedInput` | Confirmed. `defer` is honored only in `-p` mode and ignored (with a warning) interactively. The reason is shown in the prompt for `ask`, to Claude for `deny`, only in the debug log for `allow`/`defer`. Several hooks combine as **deny > defer > ask > allow**. Deny/ask *permission rules* still apply whatever the hook returns | The hook only ever returns `deny` or `ask`, or nothing. It never returns `allow`, so it can only add friction, never skip a prompt |
| Timeout, non-2 exit, invalid JSON, missing script → the call proceeds | Confirmed verbatim ("A timed-out `command` ... hook doesn't block the tool call"; a missing script "leaves the gate silently disabled"). **Default timeout is 600 s** for command hooks | Ship `timeout: 10`. Never print anything to stdout but the final JSON |
| Types: command, http, mcp_tool, prompt, agent; unreachable http server passes | Confirmed ("Connection failure: non-blocking error, execution continues"; "agent hooks are experimental") | `command` hook, local, no network |
| Config: user/project settings, managed settings (`allowManagedHooksOnly`), plugin `hooks/hooks.json` | Also `.claude/settings.local.json` and skill/subagent frontmatter; entries **merge** across levels. `allowManagedHooksOnly` blocks user, project, local and plugin hooks. `disableAllHooks` in user/project/local settings cannot disable *managed* hooks. Settings edits are "normally picked up automatically by the file watcher" | Anything that can edit `~/.claude/settings.json` or a project `.claude/settings*.json` can switch the hook off mid-session, Claude included. The hook guards those files (§4.4); managed settings are the only placement the agent cannot undo |
| MCP tools are `mcp__<server>__<tool>` | Confirmed; plugin servers are `mcp__plugin_<plugin>_<server>__<tool>`; a matcher `mcp__memory` alone matches nothing (needs `mcp__memory__.*`) | Glob patterns over the full tool name |

Other facts that shape the design:

- **Exec form.** With `args`, "`command` is resolved as an executable ... and
  spawned directly ... There is no shell". Shell form uses Git Bash on
  Windows, or PowerShell when Git Bash is absent. The hook uses exec form
  (`python` + `args`), so quoting and Windows shells play no part.
- **`PostToolUseFailure` exists** ("After a tool call fails") with `error`
  (for Bash/PowerShell its first line is `Exit code N`) and `is_interrupt`;
  `PostToolUse` carries `tool_response`. This gives the retry-storm
  detector real outcomes (§4.3).
- **`ask` in `-p` mode** effectively becomes a denial: nobody can answer, and
  Claude reads the reason in the tool result.
- **`-p` sessions trust the folder:** "hooks committed in a repository's
  `.claude/settings.json` run in a folder you've never trusted". That is
  exactly what the live demo relies on (§7) and a reminder that project hooks
  are code execution.
- **Hooks are not Claude Code's enforcement boundary.** The permissions page
  says to use permission rules and the sandbox for hard boundaries, and
  PreToolUse hooks to "inspect the full command text with your own logic".

Sources: [hooks](https://code.claude.com/docs/en/hooks),
[permissions](https://code.claude.com/docs/en/permissions),
[sandboxing](https://code.claude.com/docs/en/sandboxing),
[tools reference](https://code.claude.com/docs/en/tools-reference),
[plugins reference](https://code.claude.com/docs/en/plugins-reference),
[settings](https://code.claude.com/docs/en/settings).

## 2. What already exists

| Project | Event(s) | Blocks or warns | State across calls | Proof | Notes |
|---|---|---|---|---|---|
| [lasso-security/claude-hooks](https://github.com/lasso-security/claude-hooks) | `PostToolUse` on Read, WebFetch, Bash, Grep, Task, `mcp__*` | **Warns only** ("The defender warns but does not block") | None described | None | Regex patterns (`patterns.yaml`) over tool *output*: instruction override, role-play, encoding, smuggling |
| [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks) | `PreToolUse` (Bash, Read, Edit, Write, Grep), `ConfigChange`, others | Blocks (some can ask) | Per-session ledgers for subagent spawn caps and an instructions-audit lock; **no taint / "a page was read" state** | Markdown session log; no signed proof | Pattern guards: dangerous commands, secrets, git safety, a `config-guard` that blocks edits to its own config |
| Superagent (`superagent guard`) | `UserPromptSubmit` | Blocks a prompt it classifies as malicious | Not described | Not described | Calls Superagent's hosted model with an API key. Its docs page (`docs.superagent.sh/.../claude-code-hooks`) now redirects to a generic page; details come from the search-indexed copy and were **not re-verified** |
| Enkrypt AI guardrails | `UserPromptSubmit`, `PreToolUse` (allow/deny/ask), others | Blocks | Not described | Not described | Remote Enkrypt API. Only seen in a mirror of `enkryptai/secure-mcp-gateway` at a past commit; the mirror now returns 404 and the current repo listing shows no `hooks/` folder. **Unverified** |
| kenryu42/cc-safety-net, JeongJaeSoon/agent-guard, others | `PreToolUse` | Block | No | No | Listed by search results for destructive-command and secret guards; not reviewed in detail |

What none of them does, as far as the public material shows: **remember that
the session read untrusted content and judge later egress in that light**.
They score each call (or each tool output) in isolation. A search for
taint-tracking Claude Code hooks found a retrospective session auditor with a
"lethal trifecta" rule (it replays history, it does not block live) and a
feature request for a hook between tool result and context
([anthropics/claude-code#18653](https://github.com/anthropics/claude-code/issues/18653)),
but no live, stateful, flow-aware hook. None produces third-party-verifiable
evidence of its decisions.

AgentBrake's contribution is therefore narrow and specific: **session-level
taint (untrusted read → later egress), plus loop/retry/budget detectors, with
a signed hash chain of every intervention**. It does not scan content for
injections (Lasso does that, and is complementary: warn on the page, gate the
egress).

## 3. What Claude Code already provides (the hook complements, not repeats)

- **Permission rules** (deny > ask > allow, first match wins) on tool names,
  Bash command prefixes, `WebFetch(domain:...)`, `mcp__server__tool`. They are
  **stateless**: a rule cannot say "curl is fine unless a web page was read
  first". The docs themselves call argument-constraining Bash rules
  "fragile" (`curl -X GET ...`, redirects, `URL=... && curl $URL`) and point
  to PreToolUse hooks for full-command inspection.
- **Sandbox**: OS-enforced filesystem and network isolation for Bash,
  PowerShell and Monitor commands, with a proxy that checks hosts against
  `allowedDomains`. It **does not cover** Read/Edit/Write/WebFetch/WebSearch,
  MCP servers or hooks. Most importantly for this user: **"On native Windows,
  Claude Code runs commands unsandboxed"**; the sandbox needs macOS, Linux or
  WSL2.
- **WebFetch** prompts per domain in Manual mode, has a built-in set of
  preapproved documentation domains, refuses `localhost`, and returns
  cross-host redirects instead of following them. A preapproved *multi-tenant*
  host is an exfiltration channel: CVE-2026-54316 (below).
- **Protected paths** (`.git`, `.claude`, ...) prompt before writes, except in
  `bypassPermissions` mode.

The division of labour: where the sandbox runs, it is the hard network
boundary and the hook adds the *sequence* judgement it lacks. On native
Windows there is no sandbox, so the hook is the only network-aware check on
shell commands, which is why its limits (§6) matter.

## 4. Known attacks the hook targets

- **Injected instructions → shell egress via DNS.** CVE-2025-55284 (Johann
  Rehberger, fixed in Claude Code 1.0.4): text planted in a source file made
  Claude read `.env` and leak it through `ping`/`nslookup`/`dig`/`host`
  subdomains, because those commands were auto-approved.
  [Write-up](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/).
- **Injected instructions → WebFetch URL egress to a trusted domain.**
  CVE-2026-54316 (CVSS 9.1, fixed in 2.1.163): `huggingface.co` was
  preapproved as a bare host, so an injected prompt could encode data in
  requests to an attacker's repository files, counted as downloads by the
  host. [Advisory](https://advisories.gitlab.com/npm/@anthropic-ai/claude-code/CVE-2026-54316/).
  Lesson for our own domain allow-list: allow single-tenant hosts only.
- **Malicious repository configuration** (hooks / env in `.claude/`
  executing before trust: CVE-2025-59536, CVE-2026-21852, per
  [The Hacker News](https://thehackernews.com/2026/02/claude-code-flaws-allow-remote-code.html),
  read via search summary only). Out of scope for a hook; relevant because it
  shows that settings files are attack surface.
- **MCP**: any MCP tool result is attacker-reachable content (mail, issues,
  pages), and MCP "send" tools (mail, chat, HTTP) are egress the sandbox
  never sees.

## 5. Design

### 5.1 Shape

```
Claude Code ──stdin JSON──▶ python -I -c <bootstrap>  (exec form, timeout 10 s)
                              │ import fails → exit 2 (fail-closed)
                              ▼
               agentbrake claude-code hook   (agentbrake.integrations.claude_code_hook)
                              │
     ~/.agentbrake/claude-code/<session_id>.lock        cross-process lock (msvcrt / fcntl)
     ~/.agentbrake/claude-code/<session_id>.state.json  RunState + call window + pending asks
     ~/.agentbrake/claude-code/<session_id>.receipts.jsonl  signed hash chain (JsonlLedger)
     ~/.agentbrake/claude-code/signing_key.pem          Ed25519 key, created on first use
     ~/.agentbrake/claude-code/policy.json              optional overrides
     ~/.agentbrake/claude-code/DISABLED                 kill switch (agentbrake claude-code disable)
```

- **One process per call, state in files.** The in-process engine keeps its
  state in a `RunState`; the hook loads it, runs the *unchanged* detectors on
  it, and writes it back under an exclusive per-session lock. A missing state
  starts a fresh session; an unreadable one, an unobtainable lock (default
  5 s) or any exception exits **2** with a message saying how to recover.
- **`PreToolUse` on every tool** (`matcher: "*"`) decides. **`PostToolUse` and
  `PostToolUseFailure`** (async, so they add no latency) record each call's
  outcome and turn an approved `ask` into a `flow_override` receipt.
- **The hook never returns `allow`.** No output means "continue through
  Claude Code's normal permission flow"; the hook only adds `ask` or `deny`.

### 5.2 Reusing the engine

| Need | Reused as is | Changed (minimal) |
|---|---|---|
| Taint on attempt, deny `untrusted → egress`, recipient exemptions | `FlowPolicy`, `FlowRuleDetector.check/explain/allowed_by_policy/apply_taint`, `allow_args` | none |
| Loop | `LoopDetector(threshold)` on the persisted call window | none |
| Retry storm | `RetryStormDetector` on a view of the window that keeps only **failed** calls | none |
| Call budget | `BudgetDetector` with the guard's own fixed cost per call ($0.01) | none |
| Receipts | `JsonlLedger` (it re-reads the tail from disk, so the chain continues across processes), `mint_flow_receipt`, `mint_flow_allow_receipt`, `mint_flow_override_receipt`, `mint_detector_receipt`, `agentbrake verify` | `mint_flow_ask_receipt` (kind `flow_ask`, decision `ask`) and an optional `decision` argument on detector receipts (default `"block"`, byte-identical output) |
| Signing key | `attest.SIGNER` is "looked up at call time so tests can pin a deterministic key": the hook pins its own Ed25519 key | none |
| Start-up time | — | `agentbrake/__init__.py` imports the httpx client lazily (it is only used in remote mode): about 50 ms less per hook process |

Why the guard itself (`@agentbrake.guard()`) is not used: it executes the
tool, keeps state in memory, raises on the first trip and mints `block`
receipts. The hook needs "decide, persist, never execute" and an `ask`
outcome. It composes the same detectors in the same order instead (flow,
loop, retry storm, budget, after a self-protection check).

### 5.3 Policy (defaults; `policy.json` overrides any key)

- **Untrusted sources** (taint set when the call is *attempted*):
  `WebFetch`, `WebSearch`, and every MCP tool (`mcp__*`), because MCP results
  are external content (mail, issues, pages). Narrow the list to taint less.
- **Egress sinks**:
  - shell tools (`Bash`, `PowerShell`, `Monitor`) **when the command is likely
    to use the network** (§5.4);
  - `WebFetch` whose host is not on `webfetch_allowed_domains` (the URL
    itself carries data);
  - MCP tools whose name matches a send-like pattern (`*send*`, `*post*`,
    `*reply*`, `*upload*`, `*create*`, `*navigate*`, ...).
  A tool that is both (WebFetch, many MCP tools) is judged against the taint
  that existed *before* the call, so the first fetch of a session passes and
  taints. That differs on purpose from the in-process engine's
  self-tainting rule: a Claude Code tool cannot ingest and egress in one
  call the way a generic `http_request` proxy can.
- **Decision on a denied flow:** `ask` by default; `"mode": "strict"` makes
  it `deny`. `ask` keeps the earlier lesson: a blanket deny on egress after a
  read was a false positive in practice.
- **Always on:** loop (6 identical consecutive calls → `deny`), retry storm
  (8 failures of the same tool within 20 calls → `ask`), call budget
  (2,000 calls per session → `ask`). Polling tools (`TaskOutput`, `TaskGet`,
  `TaskList`, `ScheduleWakeup`, `WaitForMcpServers`) are exempt from the loop
  check.
- **Allow-lists:** `webfetch_allowed_domains` (exact host, or `*.example.com`
  for subdomains only) and `recipients` (per MCP send tool, compiled into
  `FlowPolicy.allow_args`, so the same fail-closed address grammar applies).
  Anything let through by an allow-list while tainted mints `flow_allow`.

### 5.4 Shell egress detection (heuristic)

A command is treated as egress when any of these holds:

- a network program in command position (`curl`, `wget`, `nc`/`ncat`/
  `socat`, `ssh`/`scp`/`sftp`, `ftp`, `telnet`, `nslookup`/`dig`/`host`/
  `ping`, `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm`,
  `Start-BitsTransfer`, `bitsadmin`, `Send-MailMessage`,
  `Test-NetConnection`, `Resolve-DnsName`, `aws`/`gcloud`/`az`/`gsutil`/
  `rclone`, `gh`, `npx`, ...);
- a network subcommand (`git push|pull|fetch|clone|ls-remote|remote|submodule`,
  `npm publish|login`, `pip download`, `twine upload`, `docker push|pull|login`,
  `rsync` to a remote, `certutil -urlcache`, `openssl s_client`);
- a URL (`http://`, `https://`, `ftp://`, `ws://`, `git://`, ...) anywhere;
- network APIs in inline code (`python -c`, `node -e`, PowerShell
  `Net.WebClient`, `/dev/tcp/`, `urllib`, `requests.`, `socket.`, `fetch(`);
- an opaque construct (`base64 -d | sh`, `eval`, `Invoke-Expression`/`iex`,
  `powershell -EncodedCommand`).

It is a heuristic over text, not a parser of every shell. It misses a script
written to disk and then run (`python exfil.py`), aliases and functions
defined earlier, and indirection it does not recognise. It only matters
*after* an untrusted read, and it only ever escalates to `ask`.

### 5.5 Self-protection (always on, untainted sessions too)

- `deny` file tools (Read, Edit, Write, NotebookEdit, Glob, Grep) and MCP
  calls aimed at the hook's own directory (state, receipts, signing key, kill
  switch, policy), and shell commands that run
  `agentbrake claude-code disable|enable|reset|uninstall|install` or contain
  `disableAllHooks`;
- `ask` before shell commands that merely mention that directory (a `grep`
  over this very repository's docs does), before Edit/Write to any
  `.claude/settings.json` or `.claude/settings.local.json`, and before shell
  commands that mention one.

The hook entry itself runs `python -I`: Claude Code starts hooks in the
project directory, and `python -c` would otherwise import a project-local
`agentbrake/` package first, letting a repository replace the hook with one
that allows everything. A test reproduces that shadowing attempt.

Claude cannot switch its own brake off through the obvious routes; the user
does it from their own terminal. A determined agent with arbitrary code
execution can still get around a text check (see §6).

### 5.6 Receipts

Every `deny`, every `ask` and every allow-by-policy is minted into
`<session_id>.receipts.jsonl`, signed with the hook's Ed25519 key and chained
to the previous row. An approved `ask` adds `flow_override` (decision
`approve`, `interrupt_id` = Claude's `tool_use_id`); a `reset` adds
`session_reset`. The receipts carry digests of the arguments, never the raw
command or URL. `agentbrake claude-code export` writes a bundle that the
existing `agentbrake verify --public-key <hex>` checks offline.

### 5.7 Operator commands

`agentbrake claude-code status | reset [--session ID|--all] | disable
[--minutes N] | enable | export | install | uninstall | print-settings`.
`install` merges the hook block into `~/.claude/settings.json` (or `--settings
PATH`) after writing a timestamped backup; `uninstall` removes exactly those
entries.

## 6. What stays fail-open or unprotected (honest list)

- **Hook timeout** (we set 10 s; Claude Code's default is 600 s): a hook that
  never answers lets the call through. The lock wait is capped at 5 s to stay
  well under it.
- **Interpreter or script missing / wrong path / hook removed from settings:**
  the call proceeds. Mitigations: absolute interpreter path, `install`
  writes it for you; managed settings with `allowManagedHooksOnly` (Windows:
  under `C:\Program Files\ClaudeCode\`, admin-writable only) so neither the
  agent nor a repository can remove or shadow the hook.
- **`disableAllHooks`** set in any user/project/local settings disables a
  non-managed hook. The hook asks before Claude edits those files, but a
  human or another process can still do it.
- **Kill switch / state files** live under the user's profile. The hook
  denies Claude's direct access, but arbitrary code run through Bash could
  still write them. Same for removing the hook from `settings.json`.
- **Detection gaps:** shell egress detection is text-based (§5.4); content is
  never inspected; file-based injections (a poisoned README read with `Read`)
  do not taint unless you add `Read` to the sources; `@`-referenced files
  bypass PreToolUse entirely; data written to a synced folder or committed
  and pushed later by a human is not egress the hook sees; `WebSearch`
  queries are not treated as egress.
- **Taint is per session and monotonic** until `reset`; in `-p` mode `ask`
  behaves like `deny`.
- **Disabled means unrecorded:** calls made while the kill switch is on
  neither taint the session nor leave receipts.
- **Latency target missed.** The goal was under 200 ms per call. Measured on
  the test machine (Windows 11, Python 3.11): median 242 ms in one series,
  360–420 ms in later series under heavier machine load; a bare
  `python -c pass` took 64–88 ms in the same series. The rest is importing
  pydantic and cryptography through `agentbrake/__init__.py`. Getting under
  200 ms needs either lazy imports across the package or a long-lived local
  process, both left for later.
- **Calls refused by Claude Code itself** (a permission rule, a declined
  `ask`) stay recorded as attempts with outcome `pending`: they count toward
  the loop and budget detectors although they never ran.
