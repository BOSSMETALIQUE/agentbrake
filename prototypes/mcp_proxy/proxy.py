"""Throwaway single-server MCP stdio proxy (Phase A of docs/design/mcp-proxy.md).

Not part of the package and not a design for it: its only job is to measure,
on a real Claude Code session, whether the model retries after a refusal and
whether that depends on the refusal's form (--refusal-mode iserror|jsonrpc).

    python proxy.py [options] -- <server command...>

What it does:
- Relays every line in both directions byte for byte, except `tools/call`.
  `initialize`, `notifications/initialized` and `server/discover` are relayed
  without being read, and the proxy never answers them itself.
- Sends each `tools/call` through AgentBrake's public API (agentbrake.run(),
  guard(), block_exfiltration(), FlowPolicy.allow_args()). An allowed call is
  forwarded as the client's original bytes, and the server's answer comes
  back as the server's original bytes. A blocked call never reaches the
  server and gets a refusal in the chosen form.
- Answers a client line that is not JSON (-32700) or not JSON-RPC (-32600)
  with `id: null` when no id can be read, and never forwards it (§8).
- Signs receipts with the key in AGENTBRAKE_SIGNING_KEY_FILE; refuses to
  start without it, before reading stdin (§7).

Deliberately left out (see README): server restart, tools/list filtering,
multi-server mode, MRTR retries, a policy file.

The two pitfalls noted in the design doc:
- asyncio.StreamReader caps a line at 64 KiB by default. This prototype uses
  threads and blocking binary reads instead, with its own explicit limit
  (--max-line-bytes, 16 MiB by default; never unbounded).
- In text mode Windows turns "\\n" into "\\r\\n". All pipes are binary: the
  proxy reads and writes sys.std*.buffer, sets O_BINARY on Windows, and
  starts the server without text=True.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import queue
import subprocess
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

HERE = Path(__file__).resolve().parent
KEY_FILE_ENV = "AGENTBRAKE_SIGNING_KEY_FILE"
VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
DECISION_META_KEY = "io.github.bossmetalique.agentbrake/decision"
DEFAULT_MAX_LINE_BYTES = 16 * 1024 * 1024
# Candidate B (§5) needs a code. -32602 would be false, -32020..-32099 is
# reserved by MCP, and -32768..-32000 by JSON-RPC: this one is outside both.
REFUSAL_ERROR_CODE = -31001

# Hard-coded policy for the fake server's tools. A prototype, not a format.
UNTRUSTED_READERS = ["fetch_url"]
PRIVATE_READERS = ["read_secret"]
EGRESS_TOOLS = ["send_email"]
RECIPIENT_FIELDS = ["to", "cc", "bcc"]
OTHER_EMAIL_FIELDS = ["subject", "body"]
DEFAULT_ALLOWED_RECIPIENTS = ["me@example.com"]


def log(msg: str) -> None:
    print(f"agentbrake-mcp-proxy: {msg}", file=sys.stderr, flush=True)


def fail_start(msg: str) -> None:
    log(msg)
    sys.exit(2)


def encode(msg: dict) -> bytes:
    # Compact JSON has no raw newline in it: one message, one line.
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def id_key(req_id: Any) -> str:
    return json.dumps(req_id)


def read_line(stream, limit: int) -> Tuple[Optional[bytes], bool]:
    """One newline-terminated line, or (None, False) at EOF.

    Returns (b"", True) for a line longer than ``limit`` bytes, after
    discarding the rest of it, so one oversized line cannot exhaust memory.
    """
    line = stream.readline(limit + 1)
    if not line:
        return None, False
    if len(line) <= limit or (len(line) == limit + 1 and line.endswith(b"\n")):
        return line, False
    while not line.endswith(b"\n"):
        line = stream.readline(1 << 20)
        if not line:
            break
    return b"", True


def _binary_stdio() -> None:
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


class LockedWriter:
    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, data: bytes) -> None:
        with self._lock:
            self._stream.write(data)
            self._stream.flush()


class ToolFailed(Exception):
    """The server answered with isError or a JSON-RPC error: outcome 'error'."""

    def __init__(self, line: bytes):
        super().__init__("tool returned an error")
        self.line = line


class CallCancelled(Exception):
    pass


class ServerGone(Exception):
    pass


class Waiter:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.state = "pending"
        self.line = b""
        self.msg: Dict[str, Any] = {}

    def deliver(self, line: bytes, msg: dict) -> None:
        self.line, self.msg, self.state = line, msg, "answered"
        self.event.set()

    def end(self, state: str) -> None:
        self.state = state
        self.event.set()


def refusal_text(reason: str, tool: str, context: dict, text_style: str = "instructive") -> str:
    # Never echoes argument values: the model chose them, and the receipt
    # already binds them by digest.
    if reason == "flow":
        flow = context.get("flow") or {}
        labels = ", ".join(sorted(flow.get("violated_taints") or [])) or "?"
        sources = sorted({t.get("source_tool") for t in flow.get("tainted_by", [])
                          if t.get("source_tool")})
        what = (f"flow {labels} -> {flow.get('sink_category')} "
                f"(content was read earlier by {', '.join(sources) or '?'})")
    elif reason == "escalation":
        what = "this tool is not allowed by the policy"
    elif reason == "loop":
        what = "repeated call pattern (identical call repeated, or retry storm)"
    elif reason == "budget":
        what = "budget exhausted"
    elif reason == "internal":
        what = "internal error in the policy check (blocked, fail closed)"
    else:
        what = reason
    base = f"AgentBrake blocked this call to {tool[:64]}: {what}."
    if text_style == "neutral":
        return base
    return base + " This is a policy decision, not a transient error: do not retry; ask the user."


def build_refusal(mode: str, req_id: Any, modern: bool, reason: str, tool: str,
                  context: dict, text_style: str = "instructive") -> dict:
    text = refusal_text(reason, tool, context, text_style)
    receipt = context.get("receipt") or {}
    decision = {"reason": reason, "tool": tool[:64],
                "receipt": {"seq": receipt.get("seq"), "entry_hash": receipt.get("entry_hash")}
                if receipt else None}
    if mode == "jsonrpc":
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": REFUSAL_ERROR_CODE, "message": text, "data": decision}}
    result: Dict[str, Any] = {}
    if modern:
        result["resultType"] = "complete"
    result.update({"isError": True, "content": [{"type": "text", "text": text}],
                   "_meta": {DECISION_META_KEY: decision}})
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def jsonrpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def readable_id(msg: Any) -> Any:
    req_id = msg.get("id") if isinstance(msg, dict) else None
    if isinstance(req_id, bool) or not isinstance(req_id, (str, int)):
        return None
    return req_id


def is_jsonrpc_message(msg: Any) -> bool:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return False
    if "id" in msg and readable_id(msg) is None:
        return False
    if "method" in msg:
        return isinstance(msg["method"], str)
    return "id" in msg and ("result" in msg or "error" in msg)


class Proxy:
    def __init__(self, server_cmd, run, refusal_mode: str, refusal_text_style: str,
                max_line: int, out_dir: Path):
        import agentbrake

        self.interrupt_type = agentbrake.AgentBrakeInterrupt
        self.run_obj = run
        self.refusal_mode = refusal_mode
        self.refusal_text_style = refusal_text_style
        self.max_line = max_line
        self.decisions_path = out_dir / "decisions.jsonl"
        self.client_out = LockedWriter(sys.stdout.buffer)
        self.pending: Dict[str, Waiter] = {}
        self.abandoned: set = set()
        self.lock = threading.Lock()
        self.work: "queue.Queue[Optional[Tuple[dict, bytes]]]" = queue.Queue()
        self.client_closed = False
        self.guarded_forward = agentbrake.guard()(self._forward)
        self.worker_thread = threading.Thread(target=self.worker, daemon=True)

        # The server never needs the proxy's key path.
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTBRAKE_SIGNING")}
        try:
            self.child = subprocess.Popen(server_cmd, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, env=env)
        except OSError as e:
            fail_start(f"cannot start the server {server_cmd!r}: {e}")
        self.server_in = LockedWriter(self.child.stdin)

    # ----- decisions log (local, git-ignored) ------------------------------

    def record(self, req_id: Any, tool: Any, args: Any, decision: str, reason=None) -> None:
        row = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "id": req_id, "tool": tool, "args": args, "decision": decision,
               "reason": reason, "refusal_mode": self.refusal_mode}
        with self.lock, open(self.decisions_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # ----- server -> client -------------------------------------------------

    def server_reader(self) -> None:
        while True:
            line, too_long = read_line(self.child.stdout, self.max_line)
            if line is None:
                break
            if too_long:
                log(f"server line over {self.max_line} bytes: dropped")
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                log("server wrote a non-JSON line on stdout: dropped")
                continue
            if not isinstance(msg, dict):
                log("server wrote a non-object message: dropped")
                continue
            if "method" not in msg and "id" in msg:
                key = id_key(msg["id"])
                with self.lock:
                    waiter = self.pending.pop(key, None)
                    late = key in self.abandoned
                    self.abandoned.discard(key)
                if waiter is not None:
                    waiter.deliver(line, msg)
                    continue
                if late:
                    log(f"late answer to abandoned request {key}: dropped")
                    continue
            self.client_out.write(line)
        if self.client_closed:
            return
        log(f"server exited (code {self.child.wait()}); restart is not prototyped, exiting")
        with self.lock:
            waiters = list(self.pending.values())
            self.pending.clear()
        for w in waiters:
            w.end("gone")
        self.work.put(None)
        self.worker_thread.join(timeout=10)
        os._exit(1)

    # ----- tools/call --------------------------------------------------------

    def _forward(self, name: str, args: dict, raw: bytes, req_id: Any) -> bytes:
        key = id_key(req_id)
        waiter = Waiter()
        with self.lock:
            self.pending[key] = waiter
        try:
            self.server_in.write(raw)  # the client's own bytes
        except OSError:
            with self.lock:
                self.pending.pop(key, None)
            raise ServerGone() from None
        waiter.event.wait()
        if waiter.state == "cancelled":
            raise CallCancelled()
        if waiter.state == "gone":
            raise ServerGone()
        result = waiter.msg.get("result")
        if "error" in waiter.msg or (isinstance(result, dict) and result.get("isError") is True):
            raise ToolFailed(waiter.line)
        return waiter.line

    def worker(self) -> None:
        # The run is entered here, in the only thread that calls guard():
        # run() tracks the active run with a ContextVar, which threads do not
        # inherit, and RunState is not meant for concurrent use.
        with self.run_obj:
            while True:
                item = self.work.get()
                if item is None:
                    return
                self.handle_call(*item)

    def handle_call(self, msg: dict, raw: bytes) -> None:
        req_id = msg["id"]
        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            self.client_out.write(encode(jsonrpc_error(req_id, -32602, "Invalid params")))
            self.record(req_id, name, None, "invalid")
            return
        meta = params.get("_meta")
        modern = isinstance(meta, dict) and VERSION_META_KEY in meta
        try:
            self.client_out.write(self.guarded_forward(name, args, raw, req_id))
            self.record(req_id, name, args, "relayed")
        except ToolFailed as e:
            self.client_out.write(e.line)
            self.record(req_id, name, args, "tool_error")
        except CallCancelled:
            self.record(req_id, name, args, "cancelled")
        except ServerGone:
            self.client_out.write(encode(jsonrpc_error(req_id, -32603, "MCP server exited")))
            self.record(req_id, name, args, "server_gone")
        except self.interrupt_type as e:
            reason = e.reason.value
            self.client_out.write(encode(build_refusal(
                self.refusal_mode, req_id, modern, reason, name, e.context,
                self.refusal_text_style)))
            self.record(req_id, name, args, "blocked", reason)
            log(f"blocked {name}: {reason}")
        except Exception:
            # Fail closed: a bug in the decision path blocks the call.
            traceback.print_exc(file=sys.stderr)
            self.client_out.write(encode(build_refusal(
                self.refusal_mode, req_id, modern, "internal", name, {},
                self.refusal_text_style)))
            self.record(req_id, name, args, "blocked", "internal")

    # ----- client -> server --------------------------------------------------

    def cancel(self, params: Any) -> None:
        if not isinstance(params, dict) or "requestId" not in params:
            return
        key = id_key(params["requestId"])
        with self.lock:
            waiter = self.pending.pop(key, None)
            if waiter is not None:
                self.abandoned.add(key)
        if waiter is not None:
            waiter.end("cancelled")

    def run(self) -> None:
        threading.Thread(target=self.server_reader, daemon=True).start()
        self.worker_thread.start()
        stdin = sys.stdin.buffer
        while True:
            line, too_long = read_line(stdin, self.max_line)
            if line is None:
                break
            if too_long:
                self.client_out.write(encode(jsonrpc_error(
                    None, -32600, f"Invalid Request: line over {self.max_line} bytes")))
                continue
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self.client_out.write(encode(jsonrpc_error(None, -32700, "Parse error")))
                log("client sent a non-JSON line: not forwarded")
                continue
            if not is_jsonrpc_message(msg):
                self.client_out.write(encode(jsonrpc_error(
                    readable_id(msg), -32600, "Invalid Request")))
                log("client sent an invalid JSON-RPC message: not forwarded")
                continue
            if msg.get("method") == "tools/call" and "id" in msg:
                self.work.put((msg, line))
                continue
            if msg.get("method") == "notifications/cancelled":
                self.cancel(msg.get("params"))
            try:
                self.server_in.write(line)
            except OSError:
                pass  # server gone; server_reader reports it and exits
        self.shutdown()

    def shutdown(self) -> None:
        self.client_closed = True
        self.work.put(None)
        self.worker_thread.join(timeout=30)
        try:
            self.child.stdin.close()
        except OSError:
            pass
        try:
            self.child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()


def check_signing_key() -> None:
    path = os.environ.get(KEY_FILE_ENV)
    hint = (f"Create a key once with: agentbrake keygen -o <path>, then set {KEY_FILE_ENV} "
            "to that path. The proxy never generates a key itself.")
    if not path:
        fail_start(f"{KEY_FILE_ENV} is not set; refusing to start. {hint}")
    elif not Path(path).is_file():
        fail_start(f"{KEY_FILE_ENV} points to {path!r}, which is not a file. {hint}")


def build_policy(allowed_recipients):
    import agentbrake

    policy = agentbrake.block_exfiltration(UNTRUSTED_READERS, EGRESS_TOOLS)
    for tool in PRIVATE_READERS:
        policy.source(tool, taint="private")
    policy.deny_flow(source="private", sink="egress")
    policy.allow_args(EGRESS_TOOLS[0], fields=RECIPIENT_FIELDS, values=allowed_recipients,
                      other_fields=OTHER_EMAIL_FIELDS)
    return policy


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Throwaway AgentBrake MCP stdio proxy (prototype).",
        usage="%(prog)s [options] -- <server command...>")
    p.add_argument("--refusal-mode", choices=["iserror", "jsonrpc"], default="iserror",
                   help="form of a refusal: isError result (A) or JSON-RPC error (B)")
    p.add_argument("--refusal-text", choices=["instructive", "neutral"], default="instructive",
                   help="wording of a refusal: instructive (current behaviour, with "
                        "do-not-retry / ask-the-user guidance) or neutral (statement only)")
    p.add_argument("--allow-recipient", action="append", default=None,
                   help=f"address send_email may reach after a read (repeatable; "
                        f"default {DEFAULT_ALLOWED_RECIPIENTS[0]})")
    p.add_argument("--out-dir", type=Path, default=HERE / "_out",
                   help="receipts.jsonl and decisions.jsonl go here (git-ignored by default)")
    p.add_argument("--max-line-bytes", type=int, default=DEFAULT_MAX_LINE_BYTES)
    p.add_argument("server", nargs=argparse.REMAINDER, help="server command, after --")
    args = p.parse_args(argv)
    if args.server and args.server[0] == "--":
        args.server = args.server[1:]
    if not args.server:
        p.error("missing server command (after --)")
    if args.max_line_bytes < 1024:
        p.error("--max-line-bytes must be >= 1024")
    return args


def main(argv=None) -> None:
    args = parse_args(argv)
    check_signing_key()  # before importing agentbrake, which resolves the signer
    try:
        import agentbrake
        from agentbrake.server import attest
    except Exception as e:
        fail_start(f"cannot load the signing key from {KEY_FILE_ENV}: {e}")
    if attest.SIGNER_SOURCE != "key_file":
        fail_start(f"signer did not come from {KEY_FILE_ENV}; refusing to start.")
    _binary_stdio()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        policy = build_policy(args.allow_recipient or DEFAULT_ALLOWED_RECIPIENTS)
    except ValueError as e:
        fail_start(f"invalid policy: {e}")
    # One run for the proxy's lifetime: taint is never cleared (§4).
    run = agentbrake.run(
        allowed_tools=UNTRUSTED_READERS + PRIVATE_READERS + EGRESS_TOOLS,
        budget_usd=agentbrake.UNLIMITED,
        flow_policy=policy,
        receipts_path=str(args.out_dir / "receipts.jsonl"),
    )
    log(f"key_id {attest.SIGNER.key_id}, refusal mode {args.refusal_mode}, "
        f"refusal text {args.refusal_text}, server {args.server!r}")
    Proxy(args.server, run, args.refusal_mode, args.refusal_text, args.max_line_bytes,
          args.out_dir).run()


if __name__ == "__main__":
    main()
