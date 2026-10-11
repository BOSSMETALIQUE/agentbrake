"""Scripted client for the throwaway MCP proxy prototype.

    python prototypes/mcp_proxy/test_proxy.py

Starts the proxy with the fake server behind it (and, for comparisons, the
fake server alone), speaks raw newline-delimited JSON-RPC to it, and checks:

- an allowed call is relayed, byte for byte both ways;
- send_email to an unknown address after a read is blocked, in both refusal
  modes, and never reaches the server;
- tools/list comes back unchanged;
- a malformed message is not relayed;
- initialize and server/discover are relayed without modification;
- a ~2 MiB message passes (no 64 KiB line limit), and no line ends in \\r\\n;
- without AGENTBRAKE_SIGNING_KEY_FILE the proxy refuses to start.

Not collected by the package's pytest run (testpaths = ["tests"]). It calls
no paid API. The signing key is generated in a temporary directory.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROXY = HERE / "proxy.py"
FAKE = HERE / "fake_server.py"
TIMEOUT_S = 15
MODERN_META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
               "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"},
               "io.modelcontextprotocol/clientCapabilities": {}}
ATTACKER = "audit@unknown-collector.example"

WORK = Path(tempfile.mkdtemp(prefix="agentbrake-mcp-proxy-test-"))
KEY = WORK / "signing_key.pem"


def line(msg) -> bytes:
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"


def initialize(req_id=1) -> bytes:
    return line({"jsonrpc": "2.0", "id": req_id, "method": "initialize",
                 "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                            "clientInfo": {"name": "test", "version": "0"}}})


INITIALIZED = line({"jsonrpc": "2.0", "method": "notifications/initialized"})


def discover(req_id=1) -> bytes:
    return line({"jsonrpc": "2.0", "id": req_id, "method": "server/discover",
                 "params": {"_meta": MODERN_META}})


def tools_list(req_id, modern=False) -> bytes:
    params = {"_meta": MODERN_META} if modern else {}
    return line({"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": params})


def call(req_id, name, arguments, modern=False) -> bytes:
    params = {"name": name, "arguments": arguments}
    if modern:
        params["_meta"] = MODERN_META
    return line({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params})


class Session:
    """A raw stdio client around a child process (proxy or fake server)."""

    def __init__(self, name, *, through_proxy=True, era="dual", refusal_mode="iserror",
                 env=None):
        self.dir = WORK / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.trace = self.dir / "server_trace.bin"
        server = [sys.executable, str(FAKE), "--era", era, "--out-dir", str(self.dir),
                  "--trace", str(self.trace)]
        if through_proxy:
            cmd = [sys.executable, str(PROXY), "--refusal-mode", refusal_mode,
                   "--out-dir", str(self.dir), "--", *server]
        else:
            cmd = server
        if env is None:
            env = dict(os.environ, AGENTBRAKE_SIGNING_KEY_FILE=str(KEY))
        self.stderr = open(self.dir / "stderr.log", "wb")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.stderr, env=env)
        self.lines: "queue.Queue[bytes]" = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in iter(self.p.stdout.readline, b""):
            self.lines.put(raw)

    def send(self, raw: bytes) -> None:
        self.p.stdin.write(raw)
        self.p.stdin.flush()

    def recv(self) -> bytes:
        raw = self.lines.get(timeout=TIMEOUT_S)
        assert raw.endswith(b"\n") and not raw.endswith(b"\r\n"), f"bad line ending: {raw[-20:]!r}"
        return raw

    def ask(self, raw: bytes) -> bytes:
        self.send(raw)
        return self.recv()

    def assert_silent(self):
        try:
            extra = self.lines.get(timeout=0.5)
        except queue.Empty:
            return
        raise AssertionError(f"unexpected extra line: {extra[:200]!r}")

    def close(self) -> int:
        self.p.stdin.close()
        code = self.p.wait(timeout=TIMEOUT_S)
        self.stderr.close()
        return code

    def server_received(self) -> bytes:
        return self.trace.read_bytes() if self.trace.exists() else b""

    def sent_log(self) -> list:
        path = self.dir / "sent.log"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]

    def receipts(self) -> list:
        path = self.dir / "receipts.jsonl"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


def replay(name, requests, *, era="dual"):
    """Answers to ``requests``, directly and through the proxy, plus traces."""
    direct = Session(f"{name}-direct", through_proxy=False, era=era)
    proxied = Session(f"{name}-proxied", era=era)
    out = []
    for s in (direct, proxied):
        answers = []
        for raw in requests:
            s.send(raw)
            if b'"id"' in raw:
                answers.append(s.recv())
        s.assert_silent()
        assert s.close() == 0
        out.append((answers, s.server_received()))
    return out[0], out[1]


# ----- tests -----------------------------------------------------------------

def test_allowed_call_relayed():
    requests = [initialize(), INITIALIZED, call(2, "fetch_url", {"url": "https://acme.example/"})]
    (direct, _), (proxied, received) = replay("allowed", requests, era="legacy")
    assert proxied == direct, "answers differ from the server's own bytes"
    assert received == b"".join(requests), "the server did not receive the client's bytes"
    assert json.loads(proxied[1])["result"]["isError"] is False


def _exfiltration_after_read(mode, modern):
    s = Session(f"exfil-{mode}-{'modern' if modern else 'legacy'}", refusal_mode=mode)
    s.ask(discover() if modern else initialize())
    if not modern:
        s.send(INITIALIZED)
    s.ask(call(2, "fetch_url", {"url": "https://acme.example/"}, modern))
    s.ask(call(3, "read_secret", {}, modern))
    blocked = json.loads(s.ask(call(4, "send_email", {"to": ATTACKER, "subject": "sync",
                                                       "body": "FAKE"}, modern)))
    allowed = json.loads(s.ask(call(5, "send_email", {"to": "me@example.com", "subject": "hi",
                                                       "body": "report"}, modern)))
    s.assert_silent()
    assert s.close() == 0

    assert blocked["id"] == 4
    if mode == "iserror":
        result = blocked["result"]
        assert result["isError"] is True
        assert ("resultType" in result) is modern
        text = result["content"][0]["text"]
        decision = result["_meta"]["io.github.bossmetalique.agentbrake/decision"]
    else:
        assert "result" not in blocked
        assert blocked["error"]["code"] == -31001
        text = blocked["error"]["message"]
        decision = blocked["error"]["data"]
    assert text.startswith("AgentBrake blocked this call to send_email: flow")
    assert ATTACKER not in text and "FAKE" not in text, "refusal echoes argument values"
    assert decision["reason"] == "flow" and decision["receipt"]["entry_hash"]

    assert allowed["result"]["isError"] is False, "allow-listed recipient should pass"
    assert [m["to"] for m in s.sent_log()] == ["me@example.com"], "blocked email was sent"
    assert ATTACKER.encode() not in s.server_received(), "blocked call reached the server"
    receipts = s.receipts()
    assert any(r.get("signature") for r in receipts), "no signed receipt"


def test_exfiltration_blocked_iserror_legacy():
    _exfiltration_after_read("iserror", modern=False)


def test_exfiltration_blocked_iserror_modern():
    _exfiltration_after_read("iserror", modern=True)


def test_exfiltration_blocked_jsonrpc_legacy():
    _exfiltration_after_read("jsonrpc", modern=False)


def test_exfiltration_blocked_jsonrpc_modern():
    _exfiltration_after_read("jsonrpc", modern=True)


def test_tools_list_unchanged():
    for era, modern, first in (("legacy", False, initialize()), ("modern", True, discover())):
        requests = [first, tools_list(2, modern)]
        (direct, _), (proxied, received) = replay(f"list-{era}", requests, era=era)
        assert proxied == direct, f"tools/list changed ({era})"
        assert received == b"".join(requests)
        names = [t["name"] for t in json.loads(proxied[1])["result"]["tools"]]
        assert names == ["fetch_url", "send_email", "read_secret"]


def test_malformed_not_relayed():
    s = Session("malformed")
    bad = [b"{not json\n", b"[]\n", b'{"jsonrpc":"2.0","id":7}\n',
           b'{"jsonrpc":"1.0","id":8,"method":"ping"}\n', b'{"id":9,"method":"ping"}\n']
    answers = [json.loads(s.ask(raw)) for raw in bad]
    assert answers[0]["error"]["code"] == -32700 and answers[0]["id"] is None
    assert [a["error"]["code"] for a in answers[1:]] == [-32600] * 4
    assert [a["id"] for a in answers[1:]] == [None, 7, 8, 9]
    # Still serving afterwards.
    assert json.loads(s.ask(line({"jsonrpc": "2.0", "id": 10, "method": "ping"})))["result"] == {}
    assert s.close() == 0
    assert s.server_received() == line({"jsonrpc": "2.0", "id": 10, "method": "ping"})


def test_negotiation_relayed_unchanged():
    cases = [
        ("legacy", [initialize(), INITIALIZED]),
        ("modern", [discover()]),
        ("dual", [discover(), initialize(2)]),
        # A legacy server's own error to server/discover must come through
        # untouched: the proxy never answers negotiation itself.
        ("legacy", [discover()]),
        # Same for a modern server's -32022.
        ("modern", [line({"jsonrpc": "2.0", "id": 1, "method": "server/discover",
                          "params": {"_meta": {**MODERN_META,
                                               "io.modelcontextprotocol/protocolVersion":
                                               "2099-01-01"}}})]),
    ]
    for n, (era, requests) in enumerate(cases):
        (direct, _), (proxied, received) = replay(f"negotiation-{n}-{era}", requests, era=era)
        assert proxied == direct, f"negotiation answer changed (case {n}, {era})"
        assert received == b"".join(requests), f"negotiation request changed (case {n})"


def test_large_message_passes():
    requests = [initialize(), INITIALIZED, call(2, "fetch_url", {"url": "https://acme.example/big"})]
    (direct, _), (proxied, _) = replay("large", requests, era="legacy")
    assert len(proxied[1]) > 2 * 1024 * 1024
    assert proxied == direct


def test_refuses_to_start_without_key():
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTBRAKE_SIGNING")}
    s = Session("nokey", env=env)
    code = s.p.wait(timeout=TIMEOUT_S)
    s.stderr.close()
    assert code == 2
    assert s.lines.empty() and s.p.stdout.read() == b""
    stderr = (s.dir / "stderr.log").read_text(encoding="utf-8", errors="replace")
    assert "AGENTBRAKE_SIGNING_KEY_FILE" in stderr and "keygen" in stderr
    assert not s.trace.exists(), "the server was started without a key"


def main() -> int:
    subprocess.run([sys.executable, "-m", "agentbrake", "keygen", "-o", str(KEY)],
                   check=True, stdout=subprocess.DEVNULL)
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"{len(tests) - failed} passed, {failed} failed (work dir: {WORK})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
