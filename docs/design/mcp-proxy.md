# Design: `agentbrake mcp-proxy`

*Design document, October 2026. Status: proposal, no production code yet.
Branch `feat/mcp-proxy`, based on v0.3.5.*

## Goal

Put AgentBrake between an MCP client (Claude Code, Cursor, a custom agent)
and an MCP server, so that every `tools/call` goes through AgentBrake's
detectors (allow-list, flow/taint rules, loop and retry-storm detection,
budget) **without the user changing their agent code**. The user changes one
thing in the client configuration: the command that launches the server.

```text
MCP client ──stdio──> agentbrake mcp-proxy ──stdio──> MCP server (child process)
                      (policy, state, receipts)
```

Sources are listed at the end and cited as [S1], [S2]...

## 1. What the protocol requires of a proxy (research)

### 1.1 Two protocol eras

The current MCP revision is **2026-07-28**. It removed the `initialize`
handshake. Every request now carries its protocol version, its client
identity and its client capabilities in `params._meta`
(`io.modelcontextprotocol/protocolVersion`, `.../clientInfo`,
`.../clientCapabilities`), and the server accepts or rejects each request on
its own. An unsupported version gets `UnsupportedProtocolVersionError`
(`-32022`) listing the supported versions [S1][S2]. The spec calls this era
"modern". Revisions up to **2025-11-25** ("legacy") open with `initialize` →
response → `notifications/initialized`, and negotiate the version once per
connection [S3].

What follows for the proxy:

- Clients and servers in the field speak one era or both ("dual-era"). On
  stdio, a dual-era client probes the server with `server/discover`. It
  falls back to `initialize` on any error that is not a recognized modern
  error, or on a timeout [S2][S4][S20]. **The proxy does not take part in
  that negotiation.** It relays `server/discover`, `initialize` and
  `notifications/initialized` unchanged, and the two ends negotiate through
  it.
- The proxy needs to know the era of a request only to make the replies it
  writes itself well formed (refusals, §5). Modern results carry
  `resultType: "complete"`; clients treat an absent `resultType` as
  `"complete"` for compatibility with older servers [S1]. The era of a
  request is read from the request: `_meta["io.modelcontextprotocol/protocolVersion"]`
  present means modern; an `initialize` already relayed on this connection
  means legacy.
- In the modern era the server **never sends requests** to the client. Stdio
  servers "MUST NOT write JSON-RPC requests to stdout" [S4]. Sampling,
  elicitation and roots come back inside an `InputRequiredResult`, and the
  client retries the same `tools/call` with `inputResponses` and an opaque
  `requestState` under a **new JSON-RPC id** [S6]. In the legacy era the
  server **does** send requests to the client (`sampling/createMessage`,
  `elicitation/create`, `roots/list`) [S3]. The proxy relays both directions.
- Modern MCP is stateless: "an open connection, such as a STDIO process, is
  not a conversation or session: clients may interleave unrelated requests
  on the same transport" [S1]. This matters for AgentBrake's notion of a run
  (§4).

### 1.2 stdio framing

From the stdio binding [S4]:

- One JSON-RPC message per line, UTF-8, newline-delimited; messages **MUST
  NOT** contain embedded newlines.
- The server **MUST NOT** write anything to stdout that is not a valid MCP
  message, and **MAY** log to stderr. The client **MAY** capture, forward or
  ignore stderr and **SHOULD NOT** treat stderr output as an error signal.
- The client **MUST NOT** write anything to the server's stdin that is not a
  valid MCP message, and **MUST NOT** write JSON-RPC responses (modern).
- Shutdown: the client closes the child's stdin, waits, and then terminates
  it. On POSIX that escalates from SIGTERM to SIGKILL; on Windows it uses
  `TerminateProcess` or Job Objects. Servers **SHOULD** exit when stdin
  closes.
- If the server exits unexpectedly, the client **SHOULD** restart it. In-flight
  requests are lost and `subscriptions/listen` streams must be reopened.
- Cancellation on stdio is `notifications/cancelled` with the request id;
  the server then **MUST NOT** send anything more for that request.
- Modern change notifications (`notifications/tools/list_changed`) arrive
  only on a `subscriptions/listen` stream. They are correlated by
  `_meta["io.modelcontextprotocol/subscriptionId"]`, whose value is the id of
  the `subscriptions/listen` request [S7]. Legacy servers send
  `notifications/tools/list_changed` when they declared `tools.listChanged`
  at `initialize` [S3].

### 1.3 tools/list, tools/call and how to refuse

From the Tools page [S5] and the base protocol [S1]:

- `tools/list` is paginated (`cursor` / `nextCursor`). Servers **SHOULD**
  return tools in a deterministic order. A server's tool set **MUST NOT** vary
  per connection or as a side effect of other requests, but **MAY** vary with
  the authorization presented on the request.
- In the modern era, `tools/list` results carry caching hints: `ttlMs` and
  `cacheScope` (`"public"` or `"private"`). The spec names `"private"` as
  the right scope for "filtered list results that vary per user" [S8].
- Tool annotations **MUST** be considered untrusted unless they come from
  trusted servers. The proxy therefore never derives a classification from
  them by itself (§3).
- Proxies that aggregate several servers **SHOULD** disambiguate colliding
  names, for example by prefixing them with a server identifier, and **SHOULD
  NOT** rely on `serverInfo.name` for that [S5].
- Two error mechanisms:
  - **Protocol errors**, as JSON-RPC errors: unknown tool, requests that fail
    the schema, server errors. Example: `-32602` "Unknown tool". Clients
    **MAY** pass them to the model.
  - **Tool execution errors**, as a normal result with `isError: true`.
    Clients **SHOULD** pass them to the model "to enable self-correction".
- Error codes [S1]: the standard JSON-RPC codes (`-32700`, `-32600` to
  `-32603`) are used for general protocol failures. `-32020` to `-32099` are
  reserved for the MCP spec, and implementations **MUST NOT** emit a code
  from that range that the spec does not define. New application codes
  **SHOULD** be allocated outside `-32768..-32000`. Error responses carry the
  request id, or none when the id could not be read.
- `_meta` keys: vendor keys use a reverse-DNS prefix (`com.example/name`).
  Prefixes whose second label is `modelcontextprotocol` or `mcp` are
  reserved [S1]. Reserved keys such as `progressToken`, `traceparent` and
  `io.modelcontextprotocol/*` travel inside messages the proxy relays.
- What must be relayed unchanged: the stdio spec has no explicit rule for
  intermediaries. Over HTTP, intermediaries **MUST** forward
  `Mcp-Param-*` headers they do not recognize [S9]. The conservative rule
  adopted here: **every message the proxy does not decide on is relayed byte
  for byte**, including unknown methods, unknown fields and `_meta` keys.

### 1.4 Streamable HTTP

In 2026-07-28 [S9]:

- One HTTP endpoint, POST only. Each JSON-RPC request is its own POST, and the
  server answers with either a JSON object or a **request-scoped** SSE
  stream. The standalone GET stream, `Mcp-Session-Id` sessions and
  `Last-Event-ID` resumption were removed.
- Requests mirror body fields into headers (`MCP-Protocol-Version`,
  `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` from `x-mcp-header` schema
  annotations). This lets intermediaries route without parsing the body.
  A server that processes the body **MUST** reject a header/body mismatch with
  `400` and `-32020` (`HeaderMismatch`). Intermediaries enforcing policy on
  mirrored headers **SHOULD** reject requests whose version does not require
  that validation.
- Cancellation is closing the request's SSE stream, not a notification.
- Servers **MUST** validate `Origin` (DNS rebinding) and, locally, **SHOULD**
  bind to 127.0.0.1.
- Legacy Streamable HTTP (2025-03-26 to 2025-11-25) still had sessions, the
  GET stream, resumable streams and server-initiated requests on SSE. The
  deprecated HTTP+SSE transport (2024-11-05) is a third shape.

For a proxy, HTTP adds:

- an HTTP server stack;
- SSE relaying;
- header/body consistency whenever the proxy rewrites a body;
- three legacy shapes;
- DNS-rebinding defence;
- **authorization**, above all. "Token passthrough" is explicitly forbidden:
  an MCP server **MUST NOT** accept a token that was not issued for it [S10].
  An HTTP front end is therefore its own resource server, never a pipe for
  the client's tokens.

The Security Best Practices page also warns about proxies that spawn stdio
servers. If a proxy can be made to start commands through a network request,
an XSS in the client becomes code execution [S10].

### 1.5 The official Python SDK

`mcp` 2.3.0 (2 October 2026) supports 2026-07-28 and serves earlier revisions
from the same server [S11][S12]. It requires **Python ≥ 3.10** [S11]. Its
dependencies [S13]:
- web stack: `starlette`, `sse-starlette`, `uvicorn`, `python-multipart`;
- HTTP and async: `anyio`, `httpx2`;
- validation and auth: `pydantic>=2.12`, `jsonschema`, `pyjwt[crypto]`;
- other: `opentelemetry-api`, `pywin32` on Windows, `mcp-types`.

**Decision: hand-roll the stdio relay. No `mcp` dependency for stdio, not
even optional.**

1. AgentBrake supports Python 3.9 (`requires-python = ">=3.9"`). A core CLI
   command available only on 3.10+ would split the support matrix.
2. The required dependencies are `httpx`, `pydantic` and `cryptography`. The
   SDK would add a whole web stack to a command that opens no socket in
   stdio mode.
3. A proxy must pass through what it does not understand. The SDK is built
   to *be* a client or a server and parses messages into typed models.
   Whether that round-trip keeps every unknown field would have to be
   verified, and verified again at each SDK release. Relaying the original
   line bytes, and parsing only to decide, avoids the question.
4. The framing itself is small (§1.2). The care goes into the edge cases
   (§10: line-length limit, binary pipes on Windows, shutdown), not into
   volume.

The SDK keeps two roles:
- **Interoperability tests**: a real SDK client and server on each side of
  the proxy, in a CI job on Python 3.10+, through the `dev` extra only.
- Possibly the **HTTP front end** later, as an optional extra (§2).

### 1.6 Existing proxies and gateways

| Project | Shape | Client config | Policy and filtering | Notes |
|---|---|---|---|---|
| hoophq/mcpproxy [S14] | Aggregating daemon; Streamable HTTP front; stdio or HTTP backends | Client points at `http://127.0.0.1:8000/mcp` | Allow/deny by glob; **denied tools removed from `tools/list`**; human approval queue; JSONL audit log | Prefixes tools `<backend>_<tool>`. Serves revisions up to 2025-11-25 only: it **refuses 2026-07-28** with `-32022`, because its call budgets and rug-pull detection rely on session state. Denies server-initiated sampling and elicitation by default. In-memory state, single replica. |
| agentgateway [S15] | Aggregating gateway; stdio targets spawned per client connection | Client points at an HTTP endpoint | Tool-call policy not described on that page | Prefixes `<target>_<tool>` to avoid collisions. |
| sparfenyuk/mcp-proxy [S16] | stdio⇄HTTP transport bridge, optional named servers | `"command": "mcp-proxy", "args": [URL]` in the client's `mcpServers` | None (bridge only) | Shows the **wrap-the-command** pattern for stdio clients. |
| Docker MCP Gateway [S17] | Single centralized gateway; servers run in containers | Clients connect to the gateway; profiles select servers | Server selection by profile; credential injection; logging | No per-call blocking described on that page. |

Two integration patterns:

- **Wrap one server.** The `command` of the client's config entry becomes
  the proxy, and the original command moves into its arguments. Claude Code
  already separates its own options from the server command with `--`
  (`claude mcp add <name> -- <command> [args...]`), and `.mcp.json` stores
  `command`, `args`, `env` [S18]. This is the smallest change for a user, and
  `.mcp.json` entries can be committed to a project.
- **Aggregate.** One gateway exposes the tools of several servers under
  prefixed names. This is the only shape where one process sees the calls of
  every server, and the spec recommends prefixing for it [S5].

Two facts from the hoophq design matter here:
- **Enforcement built on sessions breaks on 2026-07-28.** AgentBrake's state
  must not depend on protocol sessions (§4).
- **Removing denied tools from the list is established practice** (§6).

## 2. Decision 1: form of the command

**v1: stdio, one server per proxy, wrapping its command.**

```text
agentbrake mcp-proxy --policy FILE [--name NAME] [--receipts PATH] [--check] -- <server command> [args...]
```

- Everything after `--` is the server command. It is started as a child
  process from an argument list (no shell), with the proxy's environment:
  the client passes `env` to the proxy, and the proxy passes it on.
- `--name` labels the server in receipts and refusal messages. It defaults
  to the `name` field of the policy file.
- `--check` validates the policy and the signing key, then exits with 0 or
  1 without starting the server. It is meant for CI and for checking a
  setup before editing a client config.
- Claude Code example:

  ```bash
  claude mcp add github -- agentbrake mcp-proxy \
      --policy ~/.agentbrake/policies/github.json \
      -- npx -y @modelcontextprotocol/server-github
  ```

  The same `command` / `args` pair goes into `.mcp.json` or Cursor's
  `mcp.json`.

Why stdio first:
- Local agents use stdio for local servers.
- It opens no listening socket, so DNS rebinding, `Origin` and token
  handling do not arise.
- It inherits the client's process lifecycle.
- The spec recommends stdio for local servers "to limit access to just the
  MCP client" [S10].

**What HTTP would require later** (plan step 7):

- **HTTP at the back** (stdio in front, a remote HTTP server behind) is the
  easy half.
  - The proxy holds the upstream credentials from its own environment, so the
    client's credentials are never forwarded.
  - It sends the body unchanged and recomputes the mirrored headers from it,
    so it cannot cause a `-32020` header mismatch.
  - It handles request-scoped SSE responses, and legacy sessions if it talks
    to a 2025-11-25 server.
  - `httpx` is already a dependency.
- **HTTP in front** (the client talks HTTP to the proxy) is the hard half.
  - It needs an HTTP server stack, as an optional extra
    (`agentbrake[mcp-http]`, possibly built on the official SDK).
  - Bind to 127.0.0.1 and validate `Origin` [S9].
  - Relay SSE, and either support or explicitly refuse the legacy HTTP
    shapes.
  - Above all, it needs an authorization design: the proxy is a resource
    server with its own tokens and never passes the client's tokens through
    [S10].
- In every mode, the proxy starts processes only from its own command line.
  Never from a network request, which is the escalation path described in
  [S10].

## 3. Decision 2: policy format

A JSON file that maps one-to-one onto the existing API. v1 adds no new
enforcement semantics.

```json
{
  "version": 1,
  "name": "workspace",
  "default": "deny",
  "tools": {
    "fetch_url":  { "class": "untrusted_source" },
    "read_inbox": { "class": "untrusted_source" },
    "read_file":  { "class": "private_source" },
    "list_files": { "class": "neutral" },
    "send_email": {
      "class": "egress",
      "allow_args": {
        "fields": ["to", "cc", "bcc"],
        "values": ["me@example.com"],
        "domains": ["corp.example"],
        "other_fields": ["subject", "body"]
      }
    }
  },
  "flows": { "deny": [["untrusted", "egress"]] },
  "loop_threshold": 4,
  "retry": { "max_calls_per_tool": 5, "window": 10, "progress_aware": true },
  "budget_usd": null
}
```

**Mapping to the existing API**

| Policy file | AgentBrake |
|---|---|
| keys of `tools` | `allowed_tools`, enforced by `EscalationDetector` |
| `"class": "untrusted_source"` | `FlowPolicy.source(tool, "untrusted")` |
| `"class": "private_source"` | `FlowPolicy.source(tool, "private")` |
| `"class": "egress"` | `FlowPolicy.sink(tool, "egress")` |
| `"class": "neutral"` | allowed, neither source nor sink |
| `allow_args` | `FlowPolicy.allow_args(tool, ...)`, same fields, same validation |
| `flows.deny` | `FlowPolicy.deny_flow(label, category)`. If absent: `[["untrusted", "egress"]]`, the same rule as `block_exfiltration` |
| `loop_threshold`, `retry` | `Run(loop_threshold=..., retry_max_calls_per_tool=..., retry_window=..., retry_progress_aware=...)` |
| `budget_usd` | `Run(budget_usd=...)`; `null` → `agentbrake.UNLIMITED` |

**How tools are classified.** The three classes follow the "lethal
trifecta": access to private data, exposure to untrusted content, and the
ability to communicate externally [S19].

- `untrusted_source`: anything that brings outside content into the context.
  Web, email, tickets, chat, issue comments, any file an outsider can write.
- `private_source`: anything that reads the user's own confidential data,
  such as local files, databases or secrets.
- `egress`: anything that can send data out, such as email, HTTP POST,
  messages, comments, pushes or uploads. That includes "write" tools whose
  output is visible to others.
- `neutral`: none of the above, for example computation, or listings that
  carry no outside content.

Rules:

- **`"default": "deny"` is the only value accepted in v1.** A tool missing
  from `tools` is hidden from `tools/list` and refused if called (§5, §6).
  This is the allow-list semantics AgentBrake already has, and it also covers
  tools that appear later through `list_changed`.
- The proxy never classifies a tool from server annotations, which are
  untrusted [S5]. A later helper (`suggest-policy`, plan step 6) may *draft*
  a file from `tools/list` and the annotations, for a human to review.
- On load, the proxy runs `FlowPolicy.validate()`, which rejects deny rules
  that can never fire and `allow_args` on a tool that is not a sink. A policy
  that loads therefore enforces what it says.
- Unknown keys anywhere in the file are an error, not ignored. A typo such
  as `"alow_args"` must not silently drop a rule.

**Budget.** The proxy sees tool calls, not model tokens. Each `ToolCall`
costs the flat estimate `ESTIMATED_COST_PER_TOOL_CALL_USD` (0.01 USD), so
`budget_usd` in a proxy is a call counter expressed in dollars. It is kept
for parity with the library, off by default (`null` → `UNLIMITED`), and
documented as an estimate. A per-tool `cost_usd` is a possible extension,
not v1.

**Limits inherited from `FlowPolicy`** (see open questions):

- A source tool introduces **one** label. A tool that is both untrusted and
  private, such as an inbox reader, must pick one. The recommended choice is
  `untrusted_source`, because `untrusted → egress` is the rule that stops
  injection-driven exfiltration.
- Deny rules are **pairs**. The exact trifecta, "block egress only when
  untrusted *and* private are both active", cannot be expressed. Adding
  `["private", "egress"]` blocks egress after any private read, which is
  stricter and will cause false positives. It is therefore opt-in, not the
  default.

## 4. Decision 3: state, and flows across servers

**Within one proxy.** The proxy is a long-lived process, so its `Run` and
`RunState` stay in memory for the life of the process. Taint, call history
(loop and retry-storm detection) and the budget accumulate there. Nothing is
written or reloaded per call.

(The request refers to "the hook" and its per-call files. This repository
contains no such hook today. The contrast holds for any integration that
starts a fresh process per call, such as a client-side pre-tool-use hook:
that process must reload its state from disk every time, and a proxy does
not.)

**What a run is for a proxy.** In the library, a `run()` is one agent task,
and taint is monotonic within it: `flow.py` says "use a fresh `run()` per
task". A proxy cannot see task boundaries, and the modern spec states that a
connection is not a conversation [S1]. **v1 therefore uses one run per proxy
process.** This errs towards over-blocking, never under-blocking: once
anything untrusted has been read, every `egress` call is blocked until the
proxy restarts (in Claude Code, a reconnect of that server). There is
deliberately no reset tool: a tool the model can call to clear taint is a
tool an injected prompt can call too. An out-of-band reset is an open
question.

Protocol sessions are deliberately not used as the scope of a run. hoophq's
proxy had to refuse 2026-07-28 because its enforcement was keyed to sessions
[S14], and AgentBrake's must work on both eras.

**Across servers** (read on server A, send through server B). Two proxies
in two processes do not see each other's taint. Options:

| Option | Verdict |
|---|---|
| A. Independent proxies, no shared state | **v1 behaviour, documented as a limitation (§9).** Flows are enforced within one server only. |
| B. Proxies share state through a file or SQLite | **Rejected.** Check-then-act across processes needs a lock around every decision, and a crashed proxy can leave the lock held. `JsonlLedger` already states that cross-process appends are not coordinated. This brings back the per-call file I/O a proxy avoids, plus a race inside a security decision. |
| C. A local daemon that every proxy queries | Workable but heavy: a second long-lived process, IPC, its own lifecycle, and authentication of local callers. Not before there is demand. |
| D. **Aggregator mode**: one proxy launches several servers and exposes their tools under prefixed names | **Chosen for cross-server flows (plan step 5).** One process, one `RunState`, so `untrusted` from `web__fetch_url` blocks `mail__send_email` with the code that exists today. This is the shape the spec and existing gateways use for multiple servers [S5][S14][S15]. |

Aggregator mode costs more than it looks:

- the proxy must answer `initialize` and `server/discover` itself, merging
  capabilities;
- it must remap JSON-RPC ids per backend in both directions, including legacy
  server-to-client requests;
- it must multiplex `subscriptions/listen` and `list_changed`;
- tool names change (`<server>__<tool>`), which breaks client-side
  permission rules that name tools.

Hence one server per proxy first.

## 5. Decision 4: what the client receives when a call is blocked

**A `tools/call` blocked by a detector gets a tool execution error: a normal
result with `isError: true`, not a JSON-RPC error.**

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "resultType": "complete",
    "isError": true,
    "content": [{
      "type": "text",
      "text": "AgentBrake blocked this call to send_email: flow untrusted -> egress (untrusted content was read earlier by fetch_url). This is a policy decision, not a transient error: do not retry; ask the user."
    }],
    "_meta": {
      "io.github.bossmetalique.agentbrake/decision": {
        "reason": "flow",
        "tool": "send_email",
        "receipt_id": "<id of the signed receipt>"
      }
    }
  }
}
```

`resultType` is included only when the request was modern (§1.1). The
`_meta` key follows the reverse-DNS vendor-prefix rule [S1].

Why `isError` rather than a JSON-RPC error:

- Clients **SHOULD** pass tool execution errors to the model, and only
  **MAY** pass protocol errors [S5]. A model that never sees why it was
  stopped tends to retry or improvise. "Policy decision, do not retry, ask
  the user" tells it what to do.
- A JSON-RPC error would need a code. `-32602` means invalid params or an
  unknown tool, which is false for a valid but forbidden call. The range
  `-32020..-32099` is off-limits [S1]. A private code outside the JSON-RPC
  range would be legal, but no client gives it any meaning.

Reasons map to messages as follows: `flow` (with the taint source),
`escalation` (see below), `loop` (identical call repeated, or retry storm),
`budget`, and `internal` (§8).

**The proxy prevents the call; it does not stop the agent.** In-process,
`AgentBrakeInterrupt` stops the run. The README's LangGraph finding is that a
returned refusal lets the agent continue, while raising an exception stops
it. Through MCP the proxy can only answer, and the client decides what comes
next. The blocked call never reaches the server.

**Exception: a tool hidden by the policy** (§6) is answered with the
protocol error **`-32602` "Unknown tool: <name>"**. That is what a server
answers for a tool it does not have [S5], and the client was never told the
tool exists. An `escalation` receipt is still minted.

**What the refusal text never contains: argument values.** A flow block on
`send_email(to=attacker@evil.com)` names the tool, the reason and the taint
source, not the address. This keeps the refusal from echoing attacker-chosen
content back into the model's context. The operator gets full detail on
stderr.

**What the receipt contains.** The existing receipt kinds, unchanged:

| Event | Receipt kind |
|---|---|
| flow block | `flow` |
| denied flow let through by `allow_args` | `flow_allow` |
| loop, retry-storm block | `loop` |
| budget block | `budget` |
| call to a tool outside the allow-list | `escalation` |

`policy_digest` keeps its current definition (the `FlowPolicy`). The proxy
adds the following to the receipt context:

- the server label (`--name`);
- the JSON-RPC request id;
- `tool_args_digest`, a digest of the arguments as flow receipts already
  carry. Never raw values.
- the client's `clientInfo` as reported. It is self-reported and
  unverified [S1], and is marked as such.

Allowed calls with no flow involved produce no receipt, as in the library.
The existing ambiguity (a retry-storm block is recorded with kind `loop`) is
inherited, not fixed here.

## 6. Decision 5: filtering tools/list

- The proxy forwards `tools/list` and removes every tool not listed in the
  policy's `tools`. It returns the rest **in the server's order**, since
  deterministic ordering is a **SHOULD** [S5].
- **Pagination**: each page is filtered on its own, and `nextCursor` is
  passed through unchanged even if a page ends up empty. The cursor belongs
  to the server.
- **Caching (modern)**: when at least one tool was removed, `cacheScope` is
  set to `"private"` and `ttlMs` is kept [S8]. The filtered list is specific
  to this policy, and the server's `"public"` would invite a shared cache to
  serve one policy's view to another client.
- **Tools that are allowed but blocked in context**, such as a sink while
  taint is active, **stay listed**. Hiding them mid-run would make the list
  depend on earlier requests, which servers **MUST NOT** do [S5], and the
  refusal message (§5) explains a block better than a tool that disappears.
- **`list_changed`** is relayed as it is. The client's next `tools/list` is
  filtered again, and a newly added tool stays hidden unless the policy names
  it. This covers new tools appearing mid-run. It does not cover an existing
  tool whose **description** changes (a "rug pull"). Pinning a hash of each
  tool definition is a possible extension, not v1.
- **Hiding is not the enforcement.** A call to a hidden tool is refused at
  `tools/call` (§5) whatever the client has cached.

## 7. Decision 6: signed receipts and the signing key

## 8. Decision 7: failure behaviour

## 9. Decision 8: limits

## 10. Decision 9: tests

## 11. Decision 10: implementation plan

## Open questions

## Sources
