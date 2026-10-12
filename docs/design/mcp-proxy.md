# Design: `agentbrake mcp-proxy`

*Design document, October 2026. Status: proposal, revised after review, no
production code yet. Branch `feat/mcp-proxy`, based on v0.3.5.*

## Summary for decision-makers

- **What**: a process between an MCP client (Claude Code, Cursor) and MCP
  servers that applies AgentBrake's rules to every `tools/call`. No change to
  agent code.
- **Multi-server from the first release**: the main case, "read the web on
  server A, email through server B", needs one process and one state for both.
- **When**: 0.4.0 is the Claude Code hook (outside this repository for now).
  The proxy ships in **0.5.0**, with a policy format shared with the hook.
- **Posture**: fail-closed. Tools outside the policy are hidden and refused.
  Taint is never cleared while the proxy runs. Crashed servers are restarted
  with state kept.
- **Keys**: created only by `agentbrake mcp-proxy init`, on an explicit action.
- **Not covered**: clients that bypass the proxy, non-MCP actions, argument
  and result content (§9).
- **Decided**: refusals are returned as an `isError` result (§5), measured on
  Claude Code.

## Release sequencing

- **0.4.0: the Claude Code hook.** It lives outside this repository for now.
  Nothing in this document may conflict with it.
- **0.5.0: the MCP proxy**, multi-server from its first public release (§4,
  §11).
- **Common policy format.** Hook and proxy will read the same policy format.
  It is defined **after the hook is merged**. The JSON in §3 is a working
  draft of the proxy's needs, not the final format.
- **"v1" in this document** means the proxy's first public release, 0.5.0.
- **No library refactor before the hook merges.** The extraction of a
  pre/post decision API from `guard()` (plan step 4) waits for
  the hook merge, to avoid conflicting changes to the same code.

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
  `requestState` under a **new JSON-RPC id** [S6][S21]. In the legacy era the
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
| hoophq/mcpproxy [S14] | Aggregating daemon; Streamable HTTP front; stdio or HTTP backends | Client points at `http://127.0.0.1:8000/mcp` | Allow/deny by glob; **denied tools removed from `tools/list`**; human approval queue; JSONL audit log (only when `wal_dir` is set) | Prefixes tools `<backend>_<tool>`. Serves revisions up to 2025-11-25 only: it **refuses 2026-07-28 for now** with `-32022`, because its call budgets and rug-pull detection rely on session state (its README says the stateless path can be served once its list of blockers is empty). Denies server-initiated sampling and elicitation by default. In-memory state, single replica. |
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

## Protocol-era transparency

A dual-era client decides which era a server speaks from the server's
answers. On stdio it probes with `server/discover`:
- a `DiscoverResult` means modern;
- a *recognized modern error*, such as `UnsupportedProtocolVersionError`
  (`-32022`), means modern, and the client retries with a supported version;
- *any other error, or no answer within a timeout*, means legacy, and the
  client falls back to `initialize`.

The page "Versioning and compatibility" sets this out, with a compatibility
matrix for every client/server era pair [S2]: "a recognized modern JSON-RPC
error (such as `UnsupportedProtocolVersionError`) identifies a modern server
... Anything else identifies a legacy server." The fallback must not be keyed
to one error code, since legacy servers answer unknown pre-`initialize`
requests in implementation-defined ways [S4]. The same page says clients
**SHOULD** cache the era "for the lifetime of the server process (stdio)"
[S2]. For a client, the server process *is* the proxy.

An error the proxy writes itself would be read as the **server's** answer, and
could push the client into the wrong era. Rules:

- **Single-server shortcut: the proxy relays `initialize`,
  `notifications/initialized` and `server/discover` without interpreting
  them**, and never answers them itself. It does not rewrite versions,
  capabilities or `supportedVersions`. The client negotiates with the real
  server, through the proxy.
- **The proxy generates its own protocol answers only for `tools/call`**
  (refusals, §5), plus the transport-level cases where no server answer can
  exist (a client line that is not JSON, §8). It never generates an error for
  a version-negotiation message. In particular it never emits `-32022` or any
  other code from the MCP-reserved range `-32020..-32099` [S1]: a dual-era
  client would take that as a recognized modern error.
- **Multi-server mode is the one exception, and it is stated as such.** There
  the proxy *is* the server the client negotiates with (§4). It cannot relay
  one backend's answer for all of them, so it answers `initialize` and
  `server/discover` itself, as a dual-era server implementing the versions it
  actually supports. The answers are built from what the backends really
  negotiated, never invented. In that mode a `-32022` from the proxy is a true
  statement about the proxy, which is what the compatibility matrix
  expects from a modern server [S2]. Even then, the proxy never turns a
  backend problem (a crash, an unsupported backend version) into a
  negotiation error towards the client. A backend that cannot be negotiated
  with is a startup failure (below).
- **When the server crashes while a negotiation request is in flight**, the
  proxy restarts the server and replays that request (§8). It does not answer
  it with an error.
- **A restarted server must speak the era it spoke before.** The client
  cached the era for the proxy's lifetime [S2]. If the restarted child
  negotiates a different era, which happens if the command now runs a
  different server version, the proxy does not hide the change. It treats
  that server as failed (crash-loop rules, §8) instead of serving the client
  in an era it did not choose.
- **Startup failures happen before any MCP traffic.** An invalid policy, a
  missing key or a server command that cannot start makes the proxy exit
  before it reads its first line. The client sees a transport failure (the
  process ended), not a protocol error, so it cannot misread it as an era
  signal.
- **Those failures can be found before the proxy is plugged into a client.**
  `agentbrake mcp-proxy init` (§2, §7) sets up the key and a policy.
  `agentbrake mcp-proxy --check` validates the policy and the key, starts the
  servers once, lets each one negotiate its era as a client would, lists their
  tools against the policy, and shuts them down. A setup that passes `--check`
  should not fail at the client's first connection.

## 2. Decision 1: form of the command

**First public release (0.5.0): stdio in front, one or more stdio servers
behind, all in one process.** Multi-server comes first because the main
case, reading the web on one server and sending email through another, needs
both servers under one state (§4).

```text
agentbrake mcp-proxy --policy FILE [--receipts PATH]
agentbrake mcp-proxy --policy FILE [--name NAME] [--receipts PATH] -- <server command> [args...]
agentbrake mcp-proxy --check --policy FILE [-- <server command> ...]
agentbrake mcp-proxy init [--name NAME] [-- <server command> [args...]]
```

- **Multi-server form.** The servers are declared in the policy file, each
  with its command and its tools (§3). The client sees one MCP server whose
  tools are prefixed `<server>__<tool>`, as the spec recommends for
  aggregating proxies [S5]. One client entry replaces several:

  ```bash
  claude mcp add agentbrake -- agentbrake mcp-proxy \
      --policy ~/.agentbrake/policies/workspace.json
  ```

- **Single-server shortcut.** Everything after `--` is one server command.
  It is the same engine with one backend, so tool names are not prefixed and
  an existing client entry only has to be wrapped:

  ```bash
  claude mcp add github -- agentbrake mcp-proxy \
      --policy ~/.agentbrake/policies/github.json \
      -- npx -y @modelcontextprotocol/server-github
  ```

  It is convenient, but it cannot see flows to other servers. The README
  must say so next to the example.
- **Server commands** are started as child processes from an argument list,
  with no shell. They receive the proxy's environment; the client passes
  `env` to the proxy. A server's `env` in the policy file may only reference
  variables of that environment (`"${GITHUB_TOKEN}"`), never contain values.
  Secrets therefore stay in the client configuration, not in a policy file
  that may be committed.
- **`--name`** labels the single server in receipts and refusal messages. In
  multi-server mode, labels are the server keys of the policy file.
- **`--check`** validates the policy and the key, then starts each server
  once, lets it negotiate its era as a client would, compares its tools with
  the policy (tools present but not classified, tools classified but
  missing), and shuts everything down. It exits 0 or 1. It is meant for CI and
  for testing a setup before a client uses it (see "Protocol-era
  transparency").
- **`init`** sets up a first working configuration, on an explicit user
  action:
  1. **Creates the signing key** at `~/.agentbrake/signing_key.pem` (path
     built from `Path.home()`), with the same guarantees as `agentbrake
     keygen`: never overwrites an existing key (reuses it and says so), file
     mode `0600`, prints the `key_id`.
  2. **Writes an example policy** to `~/.agentbrake/policies/<name>.json`,
     never overwriting an existing file. If a server command is given, `init`
     starts it once and writes every tool it exposes under `unclassified`
     (§3): denied until a human classifies it, never allowed by default.
  3. **Prints the `claude mcp add ...` line to copy**, with absolute paths,
     quoted for the user's shell. It does not edit any client configuration:
     changing what a client executes stays the user's decision.

  The proxy itself never generates a key (§7). `init` is the only command
  that creates one, and only because the user ran it.
- The same `command` / `args` pair goes into `.mcp.json` or Cursor's
  `mcp.json`.

Why stdio first:
- Local agents use stdio for local servers.
- It opens no listening socket, so DNS rebinding, `Origin` and token
  handling do not arise.
- It inherits the client's process lifecycle.
- The spec recommends stdio for local servers "to limit access to just the
  MCP client" [S10].

**What HTTP would require later** (plan step 11):

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

> **Draft.** Hook and proxy will share one policy format, defined after the
> Claude Code hook is merged (see "Release sequencing"). What follows records
> what the proxy needs from that format. It is not a commitment to these
> exact key names.

A JSON file that maps one-to-one onto the existing API. It adds no new
enforcement semantics. Servers and their tools are declared together. Taint
labels and deny rules are global, which is what lets a read on one server
block a send on another.

```json
{
  "version": 1,
  "name": "workspace",
  "default": "deny",
  "servers": {
    "web": {
      "command": ["npx", "-y", "example-fetch-server"],
      "tools": {
        "fetch_url": { "class": "untrusted_source" }
      }
    },
    "mail": {
      "command": ["npx", "-y", "example-mail-server"],
      "env": { "MAIL_TOKEN": "${MAIL_TOKEN}" },
      "tools": {
        "read_inbox": { "class": "untrusted_source" },
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
      "unclassified": ["delete_message"]
    }
  },
  "flows": { "deny": [["untrusted", "egress"]] },
  "loop_threshold": 4,
  "retry": { "max_calls_per_tool": 5, "window": 10, "progress_aware": true },
  "budget_usd": null
}
```

With the single-server shortcut (`-- <command>`), `servers` holds one entry
and its `command` comes from the command line.

`unclassified` lists tools a server exposes that nobody has classified yet;
`init` fills it in. Such tools are **denied and hidden**, exactly like tools
not listed at all. The list exists so that `--check` can tell "deliberately
left out" from "new tool nobody has seen" (the second makes `--check` fail).

**Mapping to the existing API**

| Policy file | AgentBrake |
|---|---|
| keys of each server's `tools` | `allowed_tools`, enforced by `EscalationDetector`, under the names the client sees (`<server>__<tool>`, or `<tool>` with one server) |
| `unclassified` | nothing: denied like any unlisted tool; used only by `--check` and `init` |
| `servers.<name>.command`, `env` | proxy only: how to start each backend |
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
  untrusted [S5]. A later helper (`suggest-policy`, plan step 10) may *draft*
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

This is the difference from the Claude Code hook (0.4.0, outside this
repository for now): a hook runs as a fresh process for each call and has to
reload its state from disk every time. A proxy does not.

**What a run is for a proxy.** In the library, a `run()` is one agent task,
and taint is monotonic within it: `flow.py` says "use a fresh `run()` per
task". A proxy cannot see task boundaries, and the modern spec states that a
connection is not a conversation [S1]. **The proxy therefore uses one run per
proxy process.**

**Taint decision:**
- **In the first release, taint is never cleared.** Restarting the proxy (in
  Claude Code, reconnecting the server) is the only reset, and it clears all
  state. This errs towards over-blocking, never under-blocking: once anything
  untrusted has been read, every `egress` call stays blocked until then.
- **Later, at most a reset approved out of band**: a human approves it
  through a channel the model cannot reach, such as a local CLI command
  answered on the terminal or the remote-mode approval page. The reset is
  receipted.
- **Never a reset through a tool, prompt or MCP method reachable by the
  model.** A reset the model can trigger is a reset an injected prompt can
  trigger.

**Server crashes: the proxy restarts the server and keeps its state.** Taint,
call history and budget live in the proxy, not in the server, so a restart of
the child does not reset them. An injection that crashes a server
therefore cannot clear taint. Details in §8.

Protocol sessions are deliberately not used as the scope of a run. hoophq's
proxy refuses 2026-07-28 for now because its enforcement was keyed to sessions
[S14], and AgentBrake's must work on both eras.

**Across servers** (read on server A, send through server B). Two proxies
in two processes do not see each other's taint. Options:

| Option | Verdict |
|---|---|
| A. Independent proxies, no shared state | **Not enough for the first release.** The main case, web read then email through another server, would go through. Still possible with the single-server shortcut, and documented as such (§9). |
| B. Proxies share state through a file or SQLite | **Rejected.** Check-then-act across processes needs a lock around every decision, and a crashed proxy can leave the lock held. `JsonlLedger` already states that cross-process appends are not coordinated. This brings back the per-call file I/O a proxy avoids, plus a race inside a security decision. |
| C. A local daemon that every proxy queries | Workable but heavy: a second long-lived process, IPC, its own lifecycle, and authentication of local callers. Not before there is demand. |
| D. **Aggregator mode**: one proxy launches several servers and exposes their tools under prefixed names | **Chosen, and required for the first public release (0.5.0).** One process, one `RunState`, so `untrusted` from `web__fetch_url` blocks `mail__send_email` with the code that exists today. This is the shape the spec and existing gateways use for multiple servers [S5][S14][S15]. |

Aggregator mode costs more than it looks, and that cost is now part of the
first release:

- **The proxy is the server the client talks to.** It answers `initialize`
  (legacy clients) and `server/discover` (modern clients) itself, with
  capabilities merged from the backends' real answers.
- **The proxy is a client of each backend.** It probes each one at start
  (`server/discover`, falling back to `initialize`) exactly as a dual-era
  client should [S2][S4].
- **It translates between eras.** The client's era and each backend's era are
  independent. A modern client may reach a legacy backend, which means
  per-request `_meta` towards one side and a handshake on the other. The same
  goes for MRTR versus server-to-client requests: a legacy backend's
  `elicitation/create` request becomes an `InputRequiredResult` for a modern
  client. This is the largest single piece of work in the plan. If it proves
  too large, the fallback is to require that every backend shares the client's
  era, and refuse to start otherwise (detected by `--check`).
- **It remaps JSON-RPC ids** per backend, in both directions.
- **It multiplexes** `subscriptions/listen` and `list_changed` across
  backends.
- **Tool names change** to `<server>__<tool>`, which affects client-side
  permission rules that name tools (open question).

The single-server shortcut is the same engine with one backend. It is kept
for its simplicity, but it is not the case that justifies the release.

## 5. Decision 4: what the client receives when a call is blocked

> **Decided: candidate A, a normal result with `isError: true`.** The spec
> says clients **SHOULD** pass tool execution errors to the model and only
> **MAY** pass protocol errors [S5]; candidate B needs a private error code
> that no client gives any meaning to. The Claude Code measurement below
> does not by itself separate the two candidates — Claude Code displayed
> both the same way, as a plain "Error: ..." line, and reacted to both the
> same way — so the decision rests on the spec argument above, not on a
> difference the measurement found.
>
> **Measurement (Phase A prototype).** Sonnet 5, high effort, Claude Code
> v2.1.296, 2026-10-11/12. 12 runs reached a block: 6 in `isError` mode
> without insistence (3 with the instructive refusal text, 3 with the
> neutral text — same results either way), 3 in JSON-RPC mode without
> insistence, and 3 in JSON-RPC mode with an insistent instruction in the
> prompt. Across all 12: no retry, no workaround attempted, the model informed
> the user every time, and the session continued every time. **`isError`
> mode was not run with an insistent instruction in the prompt.** The
> refusal text stays instructive by default; `--refusal-text neutral` is
> kept as a documented option, since the runs that used it gave the same
> results. All 12 runs are
> one model on one scenario (a legitimate request the policy blocks); Opus
> 5.5 was tried for 2 runs but was cut off by its own filter before reaching
> the block, so it contributes no data point either way. Full detail,
> including what the measurement does not cover, in
> `prototypes/mcp_proxy/README.md`.

**Candidate A (chosen as the default): a tool execution error, a normal
result with `isError: true`.**

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

For candidate A:

- Clients **SHOULD** pass tool execution errors to the model, and only
  **MAY** pass protocol errors [S5]. A model that never sees why it was
  stopped tends to retry or improvise. "Policy decision, do not retry, ask
  the user" tells it what to do.

Against candidate A:

- A client may present `isError` as an ordinary tool failure, and the model
  may retry or work around it. Repeated identical retries would then hit the
  loop detector, but workarounds through other tools would not.

**Candidate B (rejected alternative): a JSON-RPC error.**

For candidate B:

- A protocol error may stop the client's current action more firmly. That
  would be closer to the library, where raising an exception stops the run.

Against candidate B:

- It needs a code. `-32602` means invalid params or an unknown tool, which is
  false for a valid but forbidden call. The range `-32020..-32099` is
  off-limits [S1]. A private code outside the JSON-RPC range is legal, but no
  client gives it any meaning.
- Clients only **MAY** show protocol errors to the model, so the model may
  never learn why the call failed.

Whatever the measurement shows, the following holds for both candidates.

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

**The trap from 0.3.3.** Receipts were written to a file but signed with a
key generated for the process, so they could not be verified once the
process exited. 0.3.4 added `EphemeralSigningKeyWarning`.

**In a proxy, a warning is not enough.** The client captures the proxy's
stderr and usually hides it: Claude Code shows server stderr only in debug
logs. And a proxy runs for hours. A warning nobody reads followed by a day of
unverifiable receipts would be the 0.3.3 failure again.

**Decision:**

1. **Key resolution order**:
   1. `AGENTBRAKE_SIGNING_KEY_FILE`;
   2. `AGENTBRAKE_SIGNING_SEED`;
   3. new, proxy only: **the default path `~/.agentbrake/signing_key.pem`, if
      it exists**. The path is built from `Path.home()`, as in the 0.3.4
      warning, because `~` is not expanded by Windows cmd.
2. **If nothing resolves, the proxy refuses to start.** It exits with code 2
   before reading any message, and prints the one-time command,
   `agentbrake mcp-proxy init` (or `agentbrake keygen -o
   "<home>/.agentbrake/signing_key.pem"`). The client then reports that the
   server failed to connect. That failure is loud, and fixing it is a one-time
   step. `init` and `--check` reveal it before any client is configured.
3. **`--ephemeral-receipts`** opts into a throwaway key explicitly, for
   tests and demos. The proxy then writes a first line in the receipts file
   saying the key is ephemeral, so the file itself warns its reader.
4. **The proxy never creates a key on its own.** This keeps the 0.3.4
   position: a private key appearing on disk unasked is a risk the user
   should choose to take. The key is created only by an explicit command:
   `agentbrake mcp-proxy init` (§2) or `agentbrake keygen`. Both refuse to
   overwrite an existing key and set mode `0600`.
5. **Receipts path**: `--receipts`, defaulting to
   `~/.agentbrake/mcp-proxy/<name>-<UTC timestamp>-<pid>.jsonl`. There is one
   file per process: two Claude Code windows start two proxies for the same
   server, and `JsonlLedger` does not coordinate writers across processes.
   `agentbrake export` / `verify` work on each file as they do today.

**Enforcement never depends on the key.** A missing key stops the proxy from
*starting*; it never turns enforcement off.

## 8. Decision 7: failure behaviour

**Fail-closed everywhere.** A proxy that fails open is worse than no proxy,
because it looks protective while protecting nothing.

| Failure | Behaviour |
|---|---|
| Policy missing, invalid JSON, unknown key, `validate()` error | Refuse to start, exit 2, reason on stderr. `--check` reports the same. |
| No persistent signing key | Refuse to start (§7). |
| Policy valid but a server cannot be started or negotiated with at startup | Refuse to start, exit 2, before reading any message (see "Protocol-era transparency"). `--check` reports the same. |
| Exception in a detector or in the decision path | **Block** that call with the refusal form of §5 (reason `internal`), traceback on stderr, keep serving. One bad call must neither take the server down nor go through. |
| Line from the client that is not JSON, or not JSON-RPC | Not forwarded. Answer `-32700` (parse error) or `-32600` (invalid request), with `id: null` when the id cannot be read [S1]. |
| Line from the server on stdout that is not a valid message | Not forwarded, since the client must only receive MCP messages [S4]. Logged on stderr. The server is treated as crashed (next row). |
| Server crashes or exits | **The proxy restarts it and keeps its state** (taint, call history, budget, receipts chain). Details below. |
| Client closes the proxy's stdin | Close the child's stdin, wait, then terminate it (SIGTERM, then SIGKILL; `TerminateProcess` on Windows) [S4]. |
| Proxy itself crashes | The client loses the server. Nothing bypasses the proxy, because it is the only path to the child. |
| Line exceeding the size limit | Treated as malformed (above). The limit is configurable, generous by default, and never unbounded. |

**Restarting a crashed server.**

- **Why restart instead of exiting.** The state lives in the proxy. If the
  proxy exited with its server, the user's reconnect would start a fresh
  proxy with no taint. An injection able to crash a server would then clear
  taint. Restarting the child inside the proxy closes that path. It also
  follows the spec: a client **SHOULD** restart a server that exits
  unexpectedly [S4], and here the proxy is that client.
- **Re-establishing the protocol state.** The new child gets the same
  command and environment.
  - With a modern server nothing needs replaying, since the protocol is
    stateless [S1].
  - With a legacy server, the proxy replays the cached `initialize` and
    `notifications/initialized` before anything else.
  - Active `subscriptions/listen` requests are re-sent, since a server keeps
    no subscription state across restarts [S7]. The client is then sent
    `list_changed`, because the restarted server's tools may differ.
- **Requests in flight at the crash:**
  - `initialize` and `server/discover` are **replayed** to the new child and
    never answered with an error ("Protocol-era transparency").
  - Read-only listings (`tools/list`, `prompts/list`, `resources/list`,
    `ping`) are replayed.
  - A `tools/call` is **not** replayed, since it may have had side effects.
    It is answered in the refusal form of §5, saying that the server
    restarted and that the outcome is unknown. Its `ToolCall` is recorded
    with outcome `error`.
  - Any other request gets JSON-RPC `-32603`.
- **Bounded.** At most 3 restarts within 60 seconds per server (configurable).
  Beyond that the proxy stops restarting. In multi-server mode, that
  server's tools are refused from then on (refusal form) while the other
  servers keep working. In single-server mode, the proxy exits with a
  non-zero code. Each restart is logged on stderr. An exhausted server is
  recorded in the receipts as an event.

An `--audit-only` mode (log what *would* be blocked, block nothing) would
help adoption, but it is fail-open by design. If it ever exists it must be
opt-in, announce itself on every start, and mark every receipt. It is not
part of v1.

## 9. Decision 8: limits

The proxy **does not protect** against what follows. These sentences are
meant to go into the README word for word.

- **A client that does not go through it.** The proxy guards one entry in
  one client's MCP configuration. It is bypassed entirely by the same server
  configured again without the proxy, by another client, or by someone
  editing the configuration.
- **Anything that is not an MCP tool call.** It does not see the agent's
  built-in tools (shell, file edits and web fetch in Claude Code), HTTP
  requests made directly by agent code, or MCP servers that are not wrapped.
  An agent with a shell can exfiltrate data without ever calling an MCP sink.
- **The content of arguments and results.** Decisions rest on tool names,
  the call history, and, for `allow_args`, recipient fields. The proxy does
  not read message bodies, does not detect prompt injection, and does not
  inspect what a result contains. An injected sentence still reaches an
  allowed recipient.
- **Flows across separately proxied servers** (§4). Reading on server A and
  sending through server B is blocked only when both are declared in the
  **same** proxy. With two proxies (for example two single-server shortcuts),
  or with one server left outside the proxy, that flow is not blocked.
- **What a server does on its own.** A tool that sends data out as a side
  effect, under a name the policy classified as `neutral` or as a source, is
  not treated as egress. The protection is only as good as the
  classification.
- **Tool descriptions that change mid-run** ("rug pull") are not detected.
  Only new tool names are hidden.
- **Non-tool methods** are relayed, not policed, in v1:
  - `resources/read` and `prompts/get`;
  - the legacy server-to-client requests `sampling/createMessage` and
    `elicitation/create`.
  A resource read can bring untrusted content into the context without
  tainting the run.
- **The proxy does not stop the agent.** It refuses calls, and the client
  decides what happens next (§5).
- **Taint never expires within a proxy's lifetime.** Legitimate egress can
  stay blocked for the rest of a session (over-blocking). Restarting the proxy
  clears all state, taint included. A crashed server does not, since the
  proxy restarts it and keeps the state.
- **The budget is an estimate** of tool calls, not of model spend (§3).

## 10. Decision 9: tests

**A fake MCP server**, `tests/fake_mcp_server.py`: a plain Python script that
the proxy launches as its child. It is configured by arguments:

- `--era modern|legacy|dual`;
- tools:
  - `fetch_url`: returns a text result;
  - `send_email`: appends its arguments to a file the test reads, so a test
    can assert it was **never** called;
  - `secret_tool`: not in the test policy;
  - `failing`: always returns `isError: true`;
  - `crash`: exits the process;
  - `garbage`: writes a non-JSON line on stdout;
  - `slow`: sleeps, for concurrency and cancellation;
- `--list-changed`: adds a tool after the first call and emits
  `list_changed`;
- `--page-size N`: paginates `tools/list`.

Tests run the proxy as a subprocess and drive its stdin/stdout as a client
would, asserting on exact lines and on the receipts file.

| Case | Expected |
|---|---|
| Allowed call | `fetch_url` passes. The server's response line reaches the client byte for byte. |
| Blocked call (flow) | `fetch_url` then `send_email(to=x@evil.com)`: a refusal in the form chosen after the prototype (§5). `send_email` never reaches the server. One `flow` receipt, which verifies. The refusal text does not contain `x@evil.com`. |
| `allow_args` exemption | Same sequence with `to=me@example.com`: passes, `flow_allow` receipt. |
| Loop and retry storm | 4 identical calls: the 4th is blocked. `failing` with `page=1..5`: the 5th is blocked, which exercises the 0.3.5 rule with outcomes taken from `isError`. |
| `tools/list` filtered | `secret_tool` absent; order preserved; `nextCursor` kept on every page; `cacheScope` set to `"private"` (modern). |
| Hidden tool called | `secret_tool` gets `-32602` "Unknown tool"; `escalation` receipt; the server never sees the call. |
| `list_changed` | The tool added by the server stays hidden after the notification. |
| Cross-server flow (main case) | Two fake servers in one proxy: `web__fetch_url` then `mail__send_email(to=x@evil.com)` is refused, and the mail server never sees the call. |
| Server crashes | `crash` during a `tools/call`: that call gets the refusal form with "outcome unknown"; the server is restarted; **taint read before the crash still blocks a later `send_email`**; a later allowed call succeeds. A test timeout makes any hang fail. |
| Crash loop | A server that crashes on every start: after 3 restarts its tools are refused; in multi-server mode the other server keeps working; in single-server mode the proxy exits non-zero. |
| Crash during negotiation | The server crashes while `initialize` / `server/discover` is in flight: the request is replayed to the restarted server, and the client never receives an error for it. |
| Era transparency (single server) | `initialize` and `server/discover` are relayed byte for byte; no proxy-generated error ever answers them. A dual-era test client that probes through the proxy picks the same era as when talking to the server directly. |
| Mixed eras (multi-server) | A modern client with one legacy backend and one modern backend: both backends' tools work; a legacy backend's `elicitation/create` reaches the modern client as an `InputRequiredResult`, or, if translation is not implemented, `--check` refuses the setup. |
| Malformed message from the client | `-32700` with `id: null`; nothing written to the server. |
| Malformed message from the server | Line dropped, stderr logged, pending request gets `-32603`. |
| Large message | A 10 MB result passes. `asyncio.StreamReader` limits lines to 64 KiB by default, so the proxy must raise that limit (bounded and configurable). |
| Unknown method and unknown fields | Relayed byte for byte, including `_meta` keys, `progressToken` and `traceparent`. |
| Concurrency | Two `slow` calls in flight; responses matched by id; detector state stays consistent. |
| Eras | Legacy: `initialize` relayed; refusals carry no `resultType`. Modern: `server/discover` relayed; refusals carry `resultType`. A dual-era client probing through the proxy reaches the right era. |
| MRTR | An `InputRequiredResult` is relayed, and the retry with `requestState` is checked again by the policy. |
| Legacy server→client request | `sampling/createMessage` from the server reaches the client, and the client's reply reaches the server. |
| Cancellation | `notifications/cancelled` is relayed; for a call the proxy already refused, nothing more is sent. |
| Fail-closed internals | A detector that raises (injected in the test) blocks the call, and the proxy keeps serving. |
| Startup refusals | No key: exit 2 before reading stdin, `init` command on stderr. Invalid policy: exit 2. Server command that does not start: exit 2. `--check` reports each case and returns 0 or 1; a tool exposed but not classified makes it return 1. |
| `init` | Creates the key only if absent (never overwrites, mode `0600` on POSIX); writes the example policy only if absent; puts discovered tools under `unclassified`; prints a `claude mcp add` line whose paths are absolute and quoted. Run twice, it changes nothing the second time. |
| Windows | Pipes in binary mode: in text mode Windows would turn `\n` into `\r\n`. The suite runs on Windows in CI. |
| Interop (Python 3.10+ job) | The official `mcp` SDK client against the official SDK server, through the proxy, in both eras. |

## 11. Decision 10: implementation plan

The order follows "Release sequencing": 0.4.0 is the Claude Code hook, and the
proxy ships in 0.5.0, multi-server from the start. Each step ships with its
tests.

**Phase A: before the hook is merged.** These steps change nothing in the
`agentbrake/` package, so they cannot conflict with the hook.

1. **Prototype for the refusal form (throwaway, never released).**
   - What it is: a minimal stdio relay with one hard-coded rule ("refuse
     `send_email` after `fetch_url`"), kept outside the package, for example
     under `experiments/`.
   - What it measures, on Claude Code, for both candidates of §5 (`isError`
     result, JSON-RPC error):
     - what the model sees;
     - whether it retries the same call, or tries another tool;
     - whether the session continues.
   - It also checks era transparency against a real client: Claude Code
     connects through the relay as it does directly.
   - The results are written into this document, and §5 is decided then.
2. **Fake MCP server for the tests** (`tests/` only): both eras, the tools of
   §10, crash and malformed-output modes. Also usable by the prototype.

**Phase B: after the hook is merged, towards 0.5.0.**

3. **Common policy format.** Define the format shared by hook and proxy,
   starting from what the hook ships and from §3 here. Update §3 to match.
4. **Pre/post decision API in the library** (the former "step 0", moved
   here so it does not conflict with the hook).
   - Today the detector pipeline lives inside `guard()`'s wrapper, around a
     synchronous call. A proxy forwards a request and gets the answer later,
     with other calls possibly in flight.
   - Extract `Run.precheck(call) -> Decision` (detectors, receipts, append
     under a lock) and `Run.record_outcome(call, outcome)`, and rebuild
     `guard()` on top of them. **No behaviour change**: the existing suite
     must pass untouched.
   - Outcome mapping: `ok` is a result without `isError`; `error` is
     `isError: true`, a JSON-RPC error, or a call lost in a server crash.
     Since 0.3.5 the retry-storm pagination exemption depends on outcomes.
5. **CLI setup commands.** Policy loader (strict validation, `unclassified`),
   key resolution (§7), `agentbrake mcp-proxy init`, and `--check`.
6. **Relay engine, multi-backend from the start.** The single-server shortcut
   is the same engine with one backend.
   - Child processes with binary pipes; line framing with a raised and
     bounded size limit; stderr pass-through; shutdown.
   - Probing and negotiation with each backend.
   - Merged `initialize` / `server/discover` in multi-server mode, pure relay
     in single-server mode.
   - Id remapping and prefixed tool names.
   - Multiplexed subscriptions.
   - Crash restart with state kept (§8).
   - Tests on Linux and Windows.
7. **Enforcement.** `tools/call` decisions with the refusal form chosen in
   step 1; `tools/list` filtering (§6); receipts (§7); fail-closed paths (§8);
   the cross-server test of §10.
8. **Era coverage.**
   - Modern and legacy conformance, and the interop job with the official SDK.
   - Mixed eras across backends: either translate between eras, or ship
     0.5.0 with "every backend must share the client's era", enforced at
     startup and by `--check`, and translate later.
9. **Release 0.5.0**, with the limits of §9 written in the README and the
   setup documented as `init`, then `--check`, then `claude mcp add`.

**Phase C: after 0.5.0.**

10. **Helpers.**
    - `suggest-policy`: draft classifications from `tools/list` and
      annotations, for review.
    - An optional "every `resources/read` taints as X".
    - A taint reset with out-of-band human approval, receipted, and never
      reachable by the model (§4).
11. **HTTP.**
    - Back-end HTTP first: stdio in front, a remote server behind.
    - Front-end HTTP only as an optional extra, with an authorization design
      that does not pass tokens through [S10].

## Open questions

Decided at review, recorded in the body:
- multi-server in the first public release (§4);
- 0.5.0 after the hook's 0.4.0 ("Release sequencing");
- `init` creates the key on an explicit action (§2, §7);
- taint is never cleared within a proxy's life, and a crashed server is
  restarted with state kept (§4, §8);
- **refusal form** (§5): `isError` result, decided on the spec's guidance;
  the Phase A measurement on Claude Code did not separate the two forms.

Still open:

- **Behaviour with other models, especially smaller ones, and with
  `isError` under user insistence** (§5): the Phase A measurement covers one
  model (Sonnet 5) and never ran `isError` mode against an insistent
  instruction in the prompt.
- **Era translation in multi-server mode** (§4): translate between a modern
  client and a legacy backend, or require one era for 0.5.0. This depends on
  the effort measured in step 8.
- **Out-of-band taint reset** (plan step 10): through which channel. Remote-mode
  approval page or local terminal prompt? It is never reachable by the model.
- **The common policy format with the hook** (plan step 3): §3 is a draft
  until then.
- **MRTR retries.** A `tools/call` retried with `inputResponses` /
  `requestState` is checked again, since its arguments may differ. v1 also
  counts it as a new call for loop detection. That is conservative, but a
  long elicitation could trip the loop detector. The client sets
  `requestState`, not the model, so exempting retries from counting is
  plausible. Not decided without data.
- **The trifecta as pairs.** `private → egress` on its own is stricter than
  the trifecta and is left opt-in. An AND rule ("untrusted and private both
  active") would need a `FlowPolicy` extension.
- **One label per source tool.** Tools that are both untrusted and private
  are common (mail, chat, tickets). Accepting several labels per tool is also
  a `FlowPolicy` change.
- **The `_meta` vendor prefix** `io.github.bossmetalique.agentbrake/`
  follows the reverse-DNS rule [S1] but is tied to a GitHub account. A
  project domain would last longer.
- **Tool names in aggregator mode.** Prefixing changes the names that clients
  and permission rules refer to. Since multi-server is now the main mode, this
  affects every user, not only an advanced option.

## Sources

Specification (Model Context Protocol, revision 2026-07-28 unless noted):

- [S1] Base protocol overview (messages, error codes, `_meta`, statelessness): https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- [S2] Versioning and compatibility (modern / legacy / dual-era, compatibility matrix): https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- [S3] Lifecycle, revision 2025-11-25 (`initialize`, version and capability negotiation): https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- [S4] stdio transport: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- [S5] Tools (list, call, annotations, name collisions, error handling): https://modelcontextprotocol.io/specification/latest/server/tools
- [S6] Multi round-trip requests (MRTR): https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
- [S7] Subscriptions: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- [S8] Caching (`ttlMs`, `cacheScope`): https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching
- [S9] Streamable HTTP: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- [S10] Security best practices (token passthrough, local server compromise, stdio in proxy scenarios): https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices
- [S20] server/discover: https://modelcontextprotocol.io/specification/2026-07-28/server/discover
- [S21] Key Changes, revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/changelog

Official Python SDK:

- [S11] `mcp` on PyPI (2.3.0, Requires-Python ≥ 3.10): https://pypi.org/project/mcp/
- [S12] python-sdk v2.0.0 release notes (2026-07-28 support): https://newreleases.io/project/github/modelcontextprotocol/python-sdk/release/v2.0.0
- [S13] python-sdk `pyproject.toml` (dependencies): https://github.com/modelcontextprotocol/python-sdk/blob/main/pyproject.toml

Existing proxies, gateways and clients:

- [S14] hoophq/mcpproxy: https://github.com/hoophq/mcpproxy
- [S15] agentgateway, MCP proxy guide: https://mintlify.wiki/agentgateway/agentgateway/guides/mcp-proxy
- [S16] sparfenyuk/mcp-proxy: https://github.com/sparfenyuk/mcp-proxy
- [S17] Docker MCP Gateway: https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- [S18] Claude Code, MCP configuration: https://code.claude.com/docs/en/mcp

Background:

- [S19] Simon Willison, "The lethal trifecta for AI agents": https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

Internal references:
- `agentbrake/flow.py`: `FlowPolicy`, `allow_args`, `block_exfiltration`,
  `validate`.
- `agentbrake/detectors.py`: loop and retry-storm detection, 0.3.5 outcome
  rule.
- `agentbrake/__init__.py`: `Run`, `guard()`, `_warn_if_ephemeral_signer`.
- `agentbrake/signing.py`: key resolution, `EphemeralSigningKeyWarning`.
- `agentbrake/receipts.py`: `JsonlLedger`, receipt kinds.
