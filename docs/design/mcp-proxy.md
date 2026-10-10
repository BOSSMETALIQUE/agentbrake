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

## 3. Decision 2: policy format

## 4. Decision 3: state, and flows across servers

## 5. Decision 4: what the client receives when a call is blocked

## 6. Decision 5: filtering tools/list

## 7. Decision 6: signed receipts and the signing key

## 8. Decision 7: failure behaviour

## 9. Decision 8: limits

## 10. Decision 9: tests

## 11. Decision 10: implementation plan

## Open questions

## Sources
