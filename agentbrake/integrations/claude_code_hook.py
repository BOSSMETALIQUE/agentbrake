"""AgentBrake as a Claude Code hook: flow control, detectors and receipts per session.

Claude Code runs a ``PreToolUse`` hook as a fresh process before every tool
call and reads its answer from stdout. This module is that process. It puts
the in-process engine — :class:`~agentbrake.flow.FlowPolicy` taint tracking,
the loop / retry-storm / budget detectors, the signed receipt chain — behind
that interface:

* **State survives between processes in files**, one set per ``session_id``
  under ``~/.agentbrake/claude-code/`` (``AGENTBRAKE_CC_HOME`` overrides it),
  read and written under an exclusive cross-process lock (``msvcrt`` on
  Windows, ``fcntl`` elsewhere).
* **Fail-closed where the platform allows it.** Any exception, an unreadable
  state file, an invalid ``policy.json`` or a lock that cannot be taken exits
  with code 2, which Claude Code treats as a block. What remains fail-open is
  outside this process: a hook that times out, or an interpreter that is
  missing (see ``docs/research/claude-code-hook.md``).
* **It never answers "allow".** No output means "carry on through Claude
  Code's normal permission flow"; the hook only adds ``ask`` or ``deny``.
* ``PostToolUse`` / ``PostToolUseFailure`` (registered async) record each
  call's outcome, which the retry-storm detector needs, and turn an ``ask``
  the user approved into a ``flow_override`` receipt.

The default policy taints the session when Claude reads untrusted content
(``WebFetch``, ``WebSearch``, any MCP tool) and, from then on, asks before a
call that looks like egress: a shell command that probably reaches the
network, a ``WebFetch`` to a host that is not allow-listed (the URL carries
data), an MCP tool that sends. Every ``ask``, ``deny`` and allow-by-policy is
signed into ``<session_id>.receipts.jsonl``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Dict, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .. import receipts, signing
from ..detectors import BudgetDetector, LoopDetector, RetryStormDetector
from ..flow import FlowPolicy, FlowRuleDetector
from ..server import attest
from ..types import InterruptReason, RunState, ToolCall

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

HOME_ENV = "AGENTBRAKE_CC_HOME"
# Recognizes this hook's entries in a settings.json, so install / uninstall
# touch only what they wrote.
HOOK_MARKER = "agentbrake-claude-code-hook"
TAINT = "untrusted"
EGRESS = "egress"
STATE_FORMAT = 1
# The detectors look back at most a few dozen calls; keeping more only makes
# the state file — rewritten on every call — slower.
KEEP_CALLS = 200
KEEP_PENDING = 200
# The in-process guard charges this fixed cost per call, which turns
# BudgetDetector into a call-count budget; the hook does the same.
COST_PER_CALL_USD = 0.01
DECISIONS = ("ask", "deny")
_MAX_STDIN = 64 * 1024 * 1024
_SESSION_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

DEFAULT_POLICY: Dict[str, Any] = {
    # "ask": a denied flow prompts the user. "strict": it is denied.
    "mode": "ask",
    # Taint the session when one of these is *attempted*. Globs match the
    # full tool name; every MCP tool returns outside content by default.
    "untrusted_sources": ["WebFetch", "WebSearch", "mcp__*"],
    # Tools whose `command` is a shell command, judged by shell_egress_reason.
    "shell_tools": ["Bash", "PowerShell", "Monitor"],
    # MCP tools that can send data out, by name. Heuristic — tune it.
    "mcp_sinks": [
        "mcp__*__*send*", "mcp__*__*post*", "mcp__*__*reply*", "mcp__*__*forward*",
        "mcp__*__*upload*", "mcp__*__*publish*", "mcp__*__*share*", "mcp__*__*comment*",
        "mcp__*__*webhook*", "mcp__*__*http*", "mcp__*__*fetch*", "mcp__*__*navigate*",
        "mcp__*__*create*", "mcp__*__*update*", "mcp__*__*write*", "mcp__*__*invite*",
        "mcp__*__*form_input*", "mcp__*__*computer*", "mcp__*__*notify*",
    ],
    # Read-style names that a sink pattern would otherwise catch
    # (get_comments, get_pull_request...).
    "mcp_not_sinks": [
        "mcp__*__get_*", "mcp__*__list_*", "mcp__*__read_*", "mcp__*__search_*",
        "mcp__*__query_*", "mcp__*__find_*", "mcp__*__describe_*",
    ],
    # Hosts WebFetch may reach from a tainted session: "docs.python.org", or
    # "*.example.com" for subdomains only. Prefer single-tenant hosts: a
    # multi-tenant one (github.com, huggingface.co) lets an attacker read
    # their own access logs, see CVE-2026-54316.
    "webfetch_allowed_domains": [],
    # Per MCP send tool, compiled into FlowPolicy.allow_args:
    # {"mcp__x__send_email": {"fields": [...], "values": [...], "domains": [...],
    #                          "other_fields": [...]}}
    "recipients": {},
    "loop": {
        "threshold": 6,
        "decision": "deny",
        "exempt_tools": ["TaskOutput", "TaskGet", "TaskList", "ScheduleWakeup", "WaitForMcpServers"],
    },
    "retry_storm": {"max_failures_per_tool": 8, "window": 20, "decision": "ask"},
    "budget": {"max_calls": 2000, "decision": "ask"},
    "lock_timeout_s": 5.0,
}


class HookError(Exception):
    """A condition the hook cannot decide safely on: the call is blocked (exit 2)."""


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def default_home() -> Path:
    configured = os.environ.get(HOME_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".agentbrake" / "claude-code"


@dataclass(frozen=True)
class Paths:
    home: Path

    @property
    def policy(self) -> Path:
        return self.home / "policy.json"

    @property
    def key(self) -> Path:
        return self.home / "signing_key.pem"

    @property
    def key_lock(self) -> Path:
        return self.home / "signing_key.lock"

    @property
    def disabled(self) -> Path:
        return self.home / "DISABLED"

    def state(self, session_id: str) -> Path:
        return self.home / f"{session_id}.state.json"

    def receipts(self, session_id: str) -> Path:
        return self.home / f"{session_id}.receipts.jsonl"

    def lock(self, session_id: str) -> Path:
        return self.home / f"{session_id}.lock"


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{1,63}")


def _str_list(value: Any, where: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise HookError(f"policy.json: {where} must be a list of non-empty strings")
    return list(value)


def _decision(value: Any, where: str) -> str:
    if value not in DECISIONS:
        raise HookError(f"policy.json: {where} must be one of {list(DECISIONS)}, got {value!r}")
    return str(value)


def _positive_int(value: Any, where: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise HookError(f"policy.json: {where} must be an integer >= {minimum}")
    return value


def _sink_name(tool: str) -> str:
    """Logical sink name for an MCP send tool (the source keeps the bare name)."""
    return f"{tool}(send)"


class Policy:
    """The effective hook policy: defaults overlaid with ``policy.json``.

    Unknown keys are an error, not a no-op: a typo such as ``"untrusted_source"``
    would otherwise read as protective and enforce nothing.
    """

    def __init__(self, overrides: Optional[Dict[str, Any]] = None):
        merged: Dict[str, Any] = json.loads(json.dumps(DEFAULT_POLICY))
        for key, value in (overrides or {}).items():
            if key not in DEFAULT_POLICY:
                raise HookError(f"policy.json: unknown key {key!r} (known: {sorted(DEFAULT_POLICY)})")
            if isinstance(DEFAULT_POLICY[key], dict) and key != "recipients":
                if not isinstance(value, dict):
                    raise HookError(f"policy.json: {key} must be an object")
                for sub in value:
                    if sub not in DEFAULT_POLICY[key]:
                        raise HookError(f"policy.json: unknown key {key}.{sub}")
                merged[key].update(value)
            else:
                merged[key] = value
        self.raw = merged

        if merged["mode"] not in ("ask", "strict"):
            raise HookError("policy.json: mode must be 'ask' or 'strict'")
        self.flow_decision = "deny" if merged["mode"] == "strict" else "ask"
        self.untrusted_sources = _str_list(merged["untrusted_sources"], "untrusted_sources")
        if not self.untrusted_sources:
            raise HookError(
                "policy.json: untrusted_sources is empty, so nothing could ever taint a "
                "session; use `agentbrake claude-code disable` to switch the hook off instead"
            )
        self.shell_tools = _str_list(merged["shell_tools"], "shell_tools")
        self.mcp_sinks = _str_list(merged["mcp_sinks"], "mcp_sinks")
        self.mcp_not_sinks = _str_list(merged["mcp_not_sinks"], "mcp_not_sinks")
        domains = [d.strip().lower() for d in _str_list(
            merged["webfetch_allowed_domains"], "webfetch_allowed_domains")]
        for domain in domains:
            if not _HOST_RE.fullmatch(domain):
                raise HookError(
                    f"policy.json: webfetch_allowed_domains entry {domain!r} is not a host "
                    "such as 'docs.python.org' or '*.example.com'"
                )
        self.webfetch_allowed_domains = domains

        recipients = merged["recipients"]
        if not isinstance(recipients, dict):
            raise HookError("policy.json: recipients must be an object keyed by MCP tool name")
        self.recipients: Dict[str, Dict[str, Any]] = {}
        for tool, spec in recipients.items():
            if not isinstance(spec, dict):
                raise HookError(f"policy.json: recipients[{tool!r}] must be an object")
            unknown = set(spec) - {"fields", "values", "domains", "other_fields"}
            if unknown:
                raise HookError(f"policy.json: recipients[{tool!r}] has unknown keys {sorted(unknown)}")
            try:
                # Built once here so a malformed allow-list fails at load,
                # with allow_args' own validation, not on the call it governs.
                (
                    FlowPolicy()
                    .source("(untrusted)", TAINT)
                    .sink(_sink_name(tool), EGRESS)
                    .deny_flow(TAINT, EGRESS)
                    .allow_args(_sink_name(tool), **spec)
                    .validate()
                )
            except (TypeError, ValueError) as e:
                raise HookError(f"policy.json: recipients[{tool!r}]: {e}") from None
            self.recipients[tool] = spec

        loop = merged["loop"]
        self.loop_threshold = _positive_int(loop["threshold"], "loop.threshold", minimum=2)
        self.loop_decision = _decision(loop["decision"], "loop.decision")
        self.loop_exempt = _str_list(loop["exempt_tools"], "loop.exempt_tools")
        storm = merged["retry_storm"]
        self.storm_max = _positive_int(storm["max_failures_per_tool"], "retry_storm.max_failures_per_tool", 2)
        self.storm_window = _positive_int(storm["window"], "retry_storm.window", self.storm_max)
        self.storm_decision = _decision(storm["decision"], "retry_storm.decision")
        budget = merged["budget"]
        self.max_calls = _positive_int(budget["max_calls"], "budget.max_calls")
        self.budget_decision = _decision(budget["decision"], "budget.decision")
        timeout = merged["lock_timeout_s"]
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 9:
            # Must stay under the hook's own timeout (10 s in the shipped
            # settings): a lock wait that outlives the hook fails open.
            raise HookError("policy.json: lock_timeout_s must be a number in (0, 9]")
        self.lock_timeout = float(timeout)
        # What every receipt's policy_digest commits to: the exact effective
        # rules, allow-lists included.
        self.digest = receipts.policy_digest({"claude_code_hook": merged})

    @classmethod
    def load(cls, paths: Paths) -> "Policy":
        if not paths.policy.exists():
            return cls()
        try:
            data = json.loads(paths.policy.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            raise HookError(f"cannot read {paths.policy}: {e}") from None
        if not isinstance(data, dict):
            raise HookError(f"{paths.policy} must contain a JSON object")
        return cls(data)


# ---------------------------------------------------------------------------
# Cross-process lock (Windows and POSIX)
# ---------------------------------------------------------------------------

if sys.platform == "win32":

    def _try_lock(fh: IO[bytes]) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(fh: IO[bytes]) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

else:

    def _try_lock(fh: IO[bytes]) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fh: IO[bytes]) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class FileLock:
    """Exclusive lock on a file, released when the holder exits or dies.

    Both OS primitives are tied to the open handle, so a hook killed mid-call
    (timeout, crash) never leaves a stale lock behind.
    """

    def __init__(self, path: Path, timeout: float):
        self.path = path
        self.timeout = timeout
        self._fh: Optional[IO[bytes]] = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                _try_lock(fh)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    fh.close()
                    raise HookError(
                        f"could not lock {self.path} within {self.timeout:g}s "
                        "(another hook process holds it)"
                    ) from None
                time.sleep(0.005)
        self._fh = fh
        return self

    def __exit__(self, *exc: Any) -> None:
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            _unlock(fh)
        finally:
            fh.close()


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionState:
    """Everything the engine kept in memory, for one Claude Code session."""

    session_id: str
    run: RunState
    total_calls: int = 0
    # tool_use_id -> {"index": absolute call index, "tool": name, "ask": ...}
    pending: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @classmethod
    def new(cls, session_id: str) -> "SessionState":
        return cls(session_id=session_id, run=RunState(run_id=session_id))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": STATE_FORMAT,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_calls": self.total_calls,
            "pending": self.pending,
            "run": self.run.model_dump(mode="json"),
        }

    @classmethod
    def from_dict(cls, data: Any, session_id: str) -> "SessionState":
        if not isinstance(data, dict) or data.get("format") != STATE_FORMAT:
            raise ValueError("unknown state format")
        if data.get("session_id") != session_id:
            raise ValueError("state belongs to another session")
        total = data.get("total_calls")
        pending = data.get("pending")
        if not isinstance(total, int) or not isinstance(pending, dict):
            raise ValueError("malformed counters")
        return cls(
            session_id=session_id,
            run=RunState.model_validate(data["run"]),
            total_calls=total,
            pending=pending,
            created_at=str(data.get("created_at")),
            updated_at=str(data.get("updated_at")),
        )

    def call_at(self, index: int) -> Optional[ToolCall]:
        """The recorded call with absolute index ``index``, if still in the window."""
        offset = self.total_calls - index
        if 1 <= offset <= len(self.run.calls):
            return self.run.calls[-offset]
        return None


def load_state(paths: Paths, session_id: str) -> SessionState:
    path = paths.state(session_id)
    if not path.exists():
        return SessionState.new(session_id)
    try:
        return SessionState.from_dict(json.loads(path.read_text(encoding="utf-8")), session_id)
    except Exception as e:  # noqa: BLE001 — any corruption is the same verdict
        raise HookError(
            f"session state {path} is unreadable ({type(e).__name__}: {e}). Blocking until it "
            f"is fixed; to start this session over, run in your own terminal: "
            f"agentbrake claude-code reset --session {session_id}"
        ) from None


def _replace(tmp: Path, target: Path) -> None:
    # Windows refuses to replace a file another process (indexer, antivirus)
    # has open for a moment; retry briefly instead of failing the call.
    for attempt in range(50):
        try:
            os.replace(tmp, target)
            return
        except PermissionError:
            if attempt == 49:
                raise
            time.sleep(0.01)


def save_state(paths: Paths, state: SessionState) -> None:
    state.updated_at = _now()
    del state.run.calls[:-KEEP_CALLS]
    if len(state.pending) > KEEP_PENDING:
        for key in list(state.pending)[: len(state.pending) - KEEP_PENDING]:
            del state.pending[key]
    path = paths.state(state.session_id)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(state.to_dict(), sort_keys=True), encoding="utf-8")
    _replace(tmp, path)


# ---------------------------------------------------------------------------
# Classification: what a tool call is, for the flow engine
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|scp|ssh|wss?|git|smb|ldaps?|telnet|gopher)://", re.I)
# Network programs and APIs worth flagging wherever they appear in the text.
_NETWORK_ANYWHERE = re.compile(
    r"\b(?:curl|wget|invoke-webrequest|invoke-restmethod|start-bitstransfer|nslookup"
    r"|resolve-dnsname|send-mailmessage|test-netconnection|enter-pssession|new-pssession)\b"
    r"|\binvoke-command\b[^;|\n]*-computername"
    r"|\bnet\.webclient\b|\bsystem\.net\.(?:http|sockets|webclient|mail)"
    r"|\b(?:downloadstring|downloadfile|uploadstring|uploadfile|uploaddata)\b"
    r"|/dev/(?:tcp|udp)/"
    # Library *calls* in inline code, not bare module names: `pip show httpx`
    # or `grep urllib` is not egress.
    r"|\burllib\.request\b|\burlopen\s*\(|\bhttp\.client\.\w+|\baiohttp\.clientsession\b"
    r"|\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|session|client|stream)\b"
    r"|\bsocket\.(?:socket|create_connection)\b|\bsmtplib\.\w+|\bftplib\.\w+|\bparamiko\.\w+"
    r"|\bfetch\s*\(|\bxmlhttprequest\b|\bnew\s+websocket\b|\brequire\(\s*['\"]https?['\"]\s*\)",
    re.I,
)
_OPAQUE = (
    (re.compile(r"\bbase64\b[^;&\n]*\s(?:-d|--decode|-D)\b[^;&\n]*\|\s*[\w./-]*"
                r"(?:sh|python\d*|perl|ruby|node|pwsh|powershell)\b", re.I),
     "decodes base64 into an interpreter"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "Invoke-Expression"),
    (re.compile(r"(?:^|[\s;&|(])eval\s", re.I), "eval"),
    (re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;&|\n]*\s[-/]e(?:c|n\w*)?\b", re.I),
     "encoded PowerShell command"),
)
_NETWORK_PROGRAMS = frozenset({
    "curl", "wget", "aria2c", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp",
    "ftp", "tftp", "lftp", "smbclient", "nslookup", "dig", "host", "ping", "ping6", "traceroute",
    "tracert", "mail", "mailx", "sendmail", "mutt", "http", "https", "xh", "httpie", "websocat",
    "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer", "bitsadmin",
    "send-mailmessage", "test-netconnection", "resolve-dnsname", "aws", "gcloud", "gsutil", "az",
    "azcopy", "rclone", "s3cmd", "gh", "npx", "bunx", "pnpx", "ngrok", "cloudflared",
})
_NETWORK_SUBCOMMANDS: Dict[str, frozenset] = {
    "git": frozenset({"push", "pull", "fetch", "clone", "ls-remote", "remote", "submodule",
                      "send-email", "request-pull"}),
    "npm": frozenset({"publish", "login", "adduser", "install", "i", "add", "exec"}),
    "pnpm": frozenset({"publish", "install", "i", "add", "dlx"}),
    "yarn": frozenset({"publish", "add", "dlx", "npm"}),
    "pip": frozenset({"install", "download"}),
    "pip3": frozenset({"install", "download"}),
    "uv": frozenset({"publish", "add", "install"}),
    "twine": frozenset({"upload"}),
    "poetry": frozenset({"publish", "add"}),
    "docker": frozenset({"push", "pull", "login"}),
    "podman": frozenset({"push", "pull", "login"}),
    "openssl": frozenset({"s_client"}),
}
_WRAPPERS = frozenset({
    "sudo", "doas", "env", "nohup", "time", "command", "exec", "builtin", "nice", "ionice",
    "timeout", "xargs", "stdbuf", "start", "start-process", "call", "&", ".", "cmd", "/c",
})
_SEGMENT_SPLIT = re.compile(r"\|\||&&|\$\(|[|;&\n(){}`]")
_WORD_RE = re.compile(r"'[^']*'|\"[^\"]*\"|\S+")
_ASSIGNMENT_RE = re.compile(r"^\$?[A-Za-z_][A-Za-z0-9_:]*=")
# host:path or host::module; the 2-character minimum leaves C:\ and C:/ alone.
_REMOTE_PATH_RE = re.compile(r"^(?:[\w.+-]+@)?[\w.-]{2,}:{1,2}")
_SCRIPT_SUFFIXES = (".exe", ".cmd", ".bat", ".com", ".ps1")


def _program_name(word: str) -> str:
    name = re.split(r"[\\/]", word.strip("'\""))[-1].lower()
    for suffix in _SCRIPT_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _segment_reason(words: List[str]) -> Optional[str]:
    i = 0
    while i < len(words):
        word = words[i]
        bare = _program_name(word)
        if _ASSIGNMENT_RE.match(word) or bare in _WRAPPERS:
            i += 1
            continue
        if word.startswith("-") or re.fullmatch(r"\d+[smhd]?", word):
            i += 1  # option or duration belonging to a wrapper (timeout 5, nice -n 10)
            continue
        break
    if i >= len(words):
        return None
    program = _program_name(words[i])
    rest = [w.strip("'\"").lower() for w in words[i + 1:]]
    if program in _NETWORK_PROGRAMS:
        return f"'{program}' reaches the network"
    subcommands = _NETWORK_SUBCOMMANDS.get(program)
    if subcommands is not None:
        hit = next((w for w in rest if w in subcommands), None)
        if hit is not None:
            return f"'{program} {hit}' reaches the network"
    if program in ("rsync", "scp") and any(_REMOTE_PATH_RE.match(w) for w in rest):
        return f"'{program}' to a remote host"
    if program == "certutil" and any("urlcache" in w or "verifyctl" in w for w in rest):
        return "'certutil -urlcache' downloads"
    if (program.startswith("python") or program == "py") and "-m" in rest:
        module = rest[rest.index("-m") + 1] if rest.index("-m") + 1 < len(rest) else ""
        if module in ("pip", "pip3") and any(w in ("install", "download") for w in rest):
            return "'python -m pip install' reaches the network"
        if module == "http.server":
            return "'python -m http.server' serves files over the network"
    return None


def shell_egress_reason(command: Any, _depth: int = 0) -> Optional[str]:
    """Why ``command`` probably reaches the network, or None.

    A heuristic over the command text, not a shell parser: it knows network
    programs in command position, network subcommands, URLs, network APIs in
    inline code and constructs that hide what runs (``eval``, ``iex``, base64
    piped into a shell). It cannot see what a script file does when run, nor
    aliases or functions defined earlier. Used only after the session read
    untrusted content, and it only ever escalates to ``ask``/``deny``.
    """
    if not isinstance(command, str):
        return "command is not a string"
    if not command.strip():
        return None
    match = _NETWORK_ANYWHERE.search(command)
    if match:
        return f"'{match.group(0).strip()}' reaches the network"
    if _URL_RE.search(command):
        return "the command contains a URL"
    for pattern, label in _OPAQUE:
        if pattern.search(command):
            return f"opaque command ({label})"
    for segment in _SEGMENT_SPLIT.split(command):
        words = _WORD_RE.findall(segment)
        reason = _segment_reason(words)
        if reason:
            return reason
        if _depth < 2:
            # Quoted strings are often code run by another shell
            # (bash -c '...', powershell -Command "...").
            for word in words:
                if len(word) > 2 and word[0] == word[-1] and word[0] in "'\"":
                    inner = shell_egress_reason(word[1:-1], _depth + 1)
                    if inner:
                        return inner
    return None


def _host_of(url: Any) -> Optional[str]:
    if not isinstance(url, str):
        return None
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    if not host or not host.isascii():
        return None
    return host.lower().rstrip(".")


def _host_allowed(host: Optional[str], allowed: Sequence[str]) -> bool:
    if host is None:
        return False
    for entry in allowed:
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def _matches(name: str, patterns: Sequence[str]) -> bool:
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in patterns)


@dataclass(frozen=True)
class Roles:
    """How the flow engine sees one call."""

    source: bool
    sink: Optional[str] = None  # logical sink name, e.g. "Bash(network)"
    sink_reason: Optional[str] = None
    host: Optional[str] = None
    host_allowed: bool = False


def classify(policy: Policy, tool: str, tool_input: Dict[str, Any]) -> Roles:
    """Source and/or sink role of a call.

    A sink's logical name differs from the tool's name (``WebFetch(url)``,
    ``Bash(network)``, ``mcp__x__send(send)``), so a tool that is both — a
    fetch, most MCP tools — is judged against the taint present *before* it
    runs. The in-process engine folds a source's own taint into its sink check
    for proxies that ingest and egress in one call; a Claude Code tool call
    cannot, and the first fetch of a session has nothing to leak yet.
    """
    source = _matches(tool, policy.untrusted_sources)
    if tool in policy.shell_tools:
        if tool == "Monitor" and "ws" in tool_input:
            reason: Optional[str] = "WebSocket watch"
        else:
            reason = shell_egress_reason(tool_input.get("command"))
        return Roles(source, f"{tool}(network)" if reason else None, reason)
    if tool == "WebFetch":
        host = _host_of(tool_input.get("url"))
        # The reason goes into receipts, so it never names the host: a
        # subdomain can be the exfiltrated data itself.
        return Roles(
            source,
            "WebFetch(url)",
            "the URL's host is not on webfetch_allowed_domains",
            host,
            _host_allowed(host, policy.webfetch_allowed_domains),
        )
    if tool.startswith("mcp__") and (
        tool in policy.recipients
        or (_matches(tool, policy.mcp_sinks) and not _matches(tool, policy.mcp_not_sinks))
    ):
        return Roles(source, _sink_name(tool), "MCP tool that can send data out")
    return Roles(source)


# ---------------------------------------------------------------------------
# Self-protection: Claude must not switch off its own brake
# ---------------------------------------------------------------------------

_CONTROL_RE = re.compile(r"claude-code\s+(?:disable|enable|reset|uninstall|install)\b", re.I)
_SETTINGS_RE = re.compile(r"\.claude[\\/][^\s'\"|;&]*settings(?:\.local)?\.json|managed-settings", re.I)
_FILE_TOOLS = {"Read": "file_path", "Edit": "file_path", "Write": "file_path",
               "NotebookEdit": "notebook_path", "Glob": "path", "Grep": "path"}
_WRITE_TOOLS = ("Edit", "Write", "NotebookEdit")


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(path)))


def _inside(path: str, root: Path) -> bool:
    try:
        candidate, base = _norm(path), _norm(str(root))
        return os.path.commonpath([candidate, base]) == base
    except ValueError:  # different drives on Windows
        return False


def _is_claude_settings(path: str) -> bool:
    p = Path(path)
    return p.name.lower() in ("settings.json", "settings.local.json") and p.parent.name.lower() == ".claude"


def protection_check(paths: Paths, tool: str, tool_input: Dict[str, Any]) -> Optional["Trip"]:
    """A deny/ask for calls that would read or switch off the hook itself."""
    home_variants = {str(paths.home).lower(), str(paths.home).lower().replace("\\", "/")}
    if tool in _FILE_TOOLS:
        target = tool_input.get(_FILE_TOOLS[tool])
        if isinstance(target, str) and target:
            if _inside(target, paths.home):
                return Trip("tamper", "deny",
                            f"{tool} on AgentBrake's own state directory ({paths.home}) is "
                            "not allowed from inside Claude Code",
                            context={"rule": "state_dir", "tool": tool})
            if tool in _WRITE_TOOLS and _is_claude_settings(target):
                return Trip("tamper", "ask",
                            f"{tool} on a Claude Code settings file ({target}) could switch "
                            "off AgentBrake's hook",
                            context={"rule": "claude_settings", "tool": tool})
        return None
    if tool.startswith("mcp__"):
        for value in tool_input.values():
            if isinstance(value, str) and any(h in value.lower().replace("\\", "/")
                                              for h in home_variants):
                return Trip("tamper", "deny",
                            "MCP call referencing AgentBrake's own state directory",
                            context={"rule": "state_dir", "tool": tool})
        return None
    command = tool_input.get("command")
    if not isinstance(command, str):
        return None
    lowered = command.lower()
    if "agentbrake" in lowered and _CONTROL_RE.search(command):
        return Trip("tamper", "deny",
                    "AgentBrake's control commands (disable/enable/reset/install/uninstall) are "
                    "for the user to run in their own terminal, not for Claude",
                    context={"rule": "control_command", "tool": tool})
    if "disableallhooks" in lowered:
        return Trip("tamper", "deny", "the command mentions disableAllHooks",
                    context={"rule": "disable_all_hooks", "tool": tool})
    flat = lowered.replace("\\", "/")
    if ".agentbrake" in flat or any(h.replace("\\", "/") in flat for h in home_variants):
        return Trip("tamper", "ask", "the command touches AgentBrake's own state directory",
                    context={"rule": "state_dir_mention", "tool": tool})
    if _SETTINGS_RE.search(command):
        return Trip("tamper", "ask", "the command touches a Claude Code settings file",
                    context={"rule": "claude_settings", "tool": tool})
    return None


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass
class Trip:
    kind: str  # "flow" | "loop" | "retry_storm" | "budget" | "tamper"
    decision: str  # "ask" | "deny"
    message: str
    flow: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None


def compact_args(tool_input: Dict[str, Any]) -> Dict[str, Any]:
    """What the call history keeps of the arguments: a digest, plus numbers.

    The digest makes identical calls compare equal (loop detection); the
    numeric arguments keep pagination visible to the retry-storm detector.
    Raw arguments — whole files for Write, commands, URLs — never reach the
    state file, which is rewritten on every call.
    """
    body = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    compact: Dict[str, Any] = {"digest": "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()}
    for key, value in tool_input.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            compact[key] = value
    return compact


def _flow_policy(policy: Policy, tool: str, roles: Roles) -> FlowPolicy:
    flow = FlowPolicy().deny_flow(TAINT, EGRESS)
    if roles.source:
        flow.source(tool, TAINT)
    if roles.sink is not None:
        flow.sink(roles.sink, EGRESS)
        if tool in policy.recipients and roles.sink == _sink_name(tool):
            flow.allow_args(roles.sink, **policy.recipients[tool])
    return flow


def _taint_summary(run: RunState) -> str:
    return ", ".join(f"{t.source_tool} (call #{t.call_index + 1})" for t in run.taints) or "none"


@dataclass
class _Context:
    paths: Paths
    policy: Policy
    state: SessionState
    ledger: receipts.JsonlLedger


def _mint(ctx: _Context, trip: Trip, tool: str, sink_call: Optional[ToolCall]) -> Dict[str, Any]:
    with _hook_signer(ctx.paths):
        if trip.kind == "flow":
            assert sink_call is not None and trip.flow is not None
            flow = receipts.flow_for_receipt(trip.flow)
            if trip.decision == "deny":
                return receipts.mint_flow_receipt(
                    ctx.ledger, run_state=ctx.state.run, sink_call=sink_call, flow=flow,
                    policy_digest_value=ctx.policy.digest,
                )
            return receipts.mint_flow_ask_receipt(
                ctx.ledger, run_state=ctx.state.run, sink_call=sink_call, flow=flow,
                policy_digest_value=ctx.policy.digest,
            )
        return receipts.mint_detector_receipt(
            ctx.ledger,
            detector_kind=trip.kind,
            run_id=ctx.state.run.run_id,
            tool=tool,
            context=trip.context or {},
            policy_digest_value=ctx.policy.digest,
            decision="block" if trip.decision == "deny" else trip.decision,
        )


def _decide_pre(ctx: _Context, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    tool: str = event["tool_name"]
    tool_input: Dict[str, Any] = event["tool_input"]
    tool_use_id = str(event.get("tool_use_id") or f"call-{ctx.state.total_calls}")
    policy, state = ctx.policy, ctx.state
    roles = classify(policy, tool, tool_input)
    trips: List[Trip] = []

    protected = protection_check(ctx.paths, tool, tool_input)
    if protected is not None:
        trips.append(protected)

    # -- flow: taint already in the session x this call's sink role ------------
    flow_detector = FlowRuleDetector(_flow_policy(policy, tool, roles))
    sink_call = ToolCall(name=roles.sink, args=tool_input) if roles.sink else None
    allowed_flow: Optional[Dict[str, Any]] = None
    if sink_call is not None:
        if flow_detector.check(state.run, sink_call) is InterruptReason.FLOW:
            explained = flow_detector.explain(state.run, sink_call)
            explained["sink_reason"] = roles.sink_reason
            if tool == "WebFetch" and roles.host_allowed:
                explained["exemption"] = {"tool": roles.sink, "allowed": True,
                                          "kind": "webfetch_domain"}
                allowed_flow = explained
            else:
                # The message (prompt / Claude) may name the host and the
                # refused recipient; the receipt keeps digests only.
                if tool == "WebFetch":
                    where = f" (host {roles.host or 'unparsable'} is not on the allow-list)"
                else:
                    where = f" ({roles.sink_reason})" if roles.sink_reason else ""
                refusal = explained.get("exemption")
                if isinstance(refusal, dict) and not refusal.get("allowed"):
                    shown = f"{refusal.get('field')}={refusal.get('value')}" if refusal.get(
                        "value") is not None else str(refusal.get("field"))
                    where += f"; recipient check failed on {shown}: {refusal.get('reason')}"
                trips.append(Trip(
                    "flow", policy.flow_decision,
                    f"this session read untrusted content via {_taint_summary(state.run)}, and "
                    f"this {tool} call looks like data leaving the machine{where}",
                    flow=explained,
                ))
        else:
            allowed_flow = flow_detector.allowed_by_policy(state.run, sink_call)
            if allowed_flow is not None:
                allowed_flow["sink_reason"] = roles.sink_reason

    # -- loop / retry storm / budget, unchanged detectors on the history -------
    history_call = ToolCall(name=tool, args=compact_args(tool_input), cost_usd=COST_PER_CALL_USD)
    if tool not in policy.loop_exempt:
        if LoopDetector(policy.loop_threshold).check(state.run, history_call) is not None:
            trips.append(Trip(
                "loop", policy.loop_decision,
                f"the same {tool} call has been made {policy.loop_threshold} times in a row; "
                "this looks like a loop",
                context={"threshold": policy.loop_threshold, "call_count": state.total_calls},
            ))
    recent = state.run.calls[-(policy.storm_window - 1):]
    failures = RunState(calls=[c for c in recent if c.outcome == "error"])
    storm = RetryStormDetector(policy.storm_max, policy.storm_window)
    if storm.check(failures, history_call) is not None:
        failed = sum(1 for c in failures.calls if c.name == tool)
        trips.append(Trip(
            "retry_storm", policy.storm_decision,
            f"{tool} failed {failed} times in the last {policy.storm_window} calls "
            "(retry storm)",
            context={"failures": failed, "window": policy.storm_window},
        ))
    budget = BudgetDetector(policy.max_calls * COST_PER_CALL_USD)
    if budget.check(state.run, history_call) is not None:
        trips.append(Trip(
            "budget", policy.budget_decision,
            f"this session reached its budget of {policy.max_calls} tool calls",
            context={"call_count": state.total_calls, "max_calls": policy.max_calls},
        ))

    output: Optional[Dict[str, Any]] = None
    ask_record: Optional[Dict[str, Any]] = None
    decision: Optional[str] = None
    if trips:
        denies = [t for t in trips if t.decision == "deny"]
        chosen = denies[0] if denies else trips[0]
        decision = chosen.decision
        row = _mint(ctx, chosen, tool, sink_call)
        output = _hook_output(decision, chosen.message, row["seq"])
        if decision == "ask":
            ask_record = {"kind": chosen.kind, "seq": row["seq"]}
            if chosen.kind == "flow":
                assert chosen.flow is not None
                ask_record.update(sink=roles.sink, flow=receipts.flow_for_receipt(chosen.flow))
    elif allowed_flow is not None:
        assert sink_call is not None
        with _hook_signer(ctx.paths):
            receipts.mint_flow_allow_receipt(
                ctx.ledger, run_state=state.run, sink_call=sink_call,
                flow=receipts.flow_for_receipt(allowed_flow), policy_digest_value=policy.digest,
            )

    if decision != "deny":
        # The call will run (or is put to the user): record the attempt and
        # taint on attempt, as the in-process guard does.
        state.run.append(history_call)
        state.total_calls += 1
        mark = flow_detector.apply_taint(state.run, ToolCall(name=tool, args={}))
        if mark is not None:
            mark.call_index = state.total_calls - 1
        state.pending[tool_use_id] = {"index": state.total_calls - 1, "tool": tool, "ask": ask_record}
    return output


def _hook_output(decision: str, message: str, seq: int) -> Dict[str, Any]:
    if decision == "ask":
        reason = (f"AgentBrake: {message}. Approve only if you expected this. "
                  f"[signed receipt #{seq}]")
    else:
        reason = (f"AgentBrake blocked this call: {message}. Do not try to work around this "
                  f"check; tell the user, who can review it. [signed receipt #{seq}]")
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def _record_outcome(ctx: _Context, event: Dict[str, Any], failed: bool) -> None:
    tool_use_id = event.get("tool_use_id")
    entry = ctx.state.pending.pop(str(tool_use_id), None) if tool_use_id else None
    if entry is None:
        return
    call = ctx.state.call_at(int(entry.get("index", -1)))
    if call is not None:
        call.outcome = "error" if failed else "ok"
    ask = entry.get("ask")
    if not ask:
        return
    # The tool ran, so the user approved the ask: chain that decision.
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    with _hook_signer(ctx.paths):
        if ask.get("kind") == "flow" and ask.get("sink"):
            receipts.mint_flow_override_receipt(
                ctx.ledger, run_state=ctx.state.run,
                sink_call=ToolCall(name=ask["sink"], args=tool_input),
                flow=ask.get("flow") or {}, interrupt_id=str(tool_use_id),
                policy_digest_value=ctx.policy.digest,
            )
        else:
            receipts.mint_detector_receipt(
                ctx.ledger, detector_kind=str(ask.get("kind")), run_id=ctx.state.run.run_id,
                tool=str(event.get("tool_name")),
                context={"interrupt_id": str(tool_use_id), "ask_receipt_seq": ask.get("seq")},
                policy_digest_value=ctx.policy.digest, decision="approve",
            )


# ---------------------------------------------------------------------------
# Signing key
# ---------------------------------------------------------------------------


def load_or_create_signer(paths: Paths) -> signing.Ed25519Signer:
    """The hook's Ed25519 key (``signing_key.pem``), created on first use."""
    if not paths.key.exists():
        with FileLock(paths.key_lock, 5.0):
            if not paths.key.exists():
                signer = signing.Ed25519Signer.generate()
                tmp = paths.key.with_name(paths.key.name + f".{os.getpid()}.tmp")
                tmp.write_bytes(signer.private_pem())
                try:  # best effort; Windows relies on the profile directory's ACL
                    tmp.chmod(0o600)
                except OSError:
                    pass
                _replace(tmp, paths.key)
    return signing.Ed25519Signer.from_pem_file(str(paths.key))


class _hook_signer:
    """Sign with the hook's own key for the duration of the block.

    ``attest.SIGNER`` is a module global looked up at call time; it is put
    back afterwards so in-process callers (tests) see no side effect.
    """

    def __init__(self, paths: Paths):
        self.paths = paths
        self._saved: Any = None

    def __enter__(self) -> None:
        self._saved = attest.SIGNER
        attest.SIGNER = load_or_create_signer(self.paths)

    def __exit__(self, *exc: Any) -> None:
        attest.SIGNER = self._saved


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def disabled_until(paths: Paths) -> Tuple[bool, Optional[float]]:
    """``(disabled, until_epoch)``. A corrupt switch file leaves the hook ON."""
    try:
        data = json.loads(paths.disabled.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, None
    except (OSError, ValueError):
        return False, None
    until = data.get("until") if isinstance(data, dict) else None
    if until is None:
        return (isinstance(data, dict), None)
    if not isinstance(until, (int, float)):
        return False, None
    return time.time() < until, float(until)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_event(raw: bytes) -> Dict[str, Any]:
    if len(raw) > _MAX_STDIN:
        raise HookError("hook input larger than 64 MiB")
    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise HookError(f"hook input is not valid JSON: {e}") from None
    if not isinstance(event, dict):
        raise HookError("hook input is not a JSON object")
    return event


def handle_event(event: Dict[str, Any], paths: Paths) -> Optional[Dict[str, Any]]:
    """Process one hook event; returns the JSON to print, if any."""
    name = event.get("hook_event_name")
    if name not in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        return None  # registered for an event it does not handle: stay out of the way
    disabled, _ = disabled_until(paths)
    if disabled:
        return None
    session_id = event.get("session_id")
    if not isinstance(session_id, str) or not _SESSION_RE.fullmatch(session_id):
        raise HookError(f"missing or malformed session_id: {session_id!r}")
    tool = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool, str) or not tool:
        raise HookError("missing tool_name")
    if not isinstance(tool_input, dict):
        raise HookError(f"tool_input for {tool} is not an object")

    policy = Policy.load(paths)
    paths.home.mkdir(parents=True, exist_ok=True)
    with FileLock(paths.lock(session_id), policy.lock_timeout):
        state_exists = paths.state(session_id).exists()
        state = load_state(paths, session_id)
        ctx = _Context(paths, policy, state, receipts.JsonlLedger(str(paths.receipts(session_id))))
        if name == "PreToolUse":
            output = _decide_pre(ctx, event)
        else:
            if not state_exists:
                return None
            _record_outcome(ctx, event, failed=(name == "PostToolUseFailure"))
            output = None
        save_state(paths, state)
    return output


def main(
    stdin: Optional[IO[bytes]] = None,
    stdout: Optional[IO[str]] = None,
    stderr: Optional[IO[str]] = None,
    home: Optional[Path] = None,
) -> int:
    """Run one hook invocation. Returns the process exit code (0, or 2 = block)."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    try:
        raw = (stdin or sys.stdin.buffer).read(_MAX_STDIN + 1)
        output = handle_event(_parse_event(raw), Paths(home or default_home()))
        if output is not None:
            out.write(json.dumps(output, ensure_ascii=True))
            out.flush()
        return 0
    except HookError as e:
        err.write(f"AgentBrake (fail-closed): {e}\n")
        return 2
    except BaseException as e:  # noqa: BLE001 — fail closed on anything at all
        err.write(
            f"AgentBrake internal error, call blocked (fail-closed): {type(e).__name__}: {e}. "
            "If this keeps blocking you, run `agentbrake claude-code disable` in your own "
            "terminal.\n"
        )
        return 2


# ---------------------------------------------------------------------------
# Operator commands (agentbrake claude-code ...)
# ---------------------------------------------------------------------------

# Run by the hook entry in settings.json. Importing AgentBrake is part of the
# guarded path: if it fails (broken install), Python would exit 1, which
# Claude Code treats as non-blocking. This wrapper turns that into exit 2.
BOOTSTRAP = (
    "import sys\n"
    "try:\n"
    "    from agentbrake.cli import main\n"
    "except BaseException as e:\n"
    "    sys.stderr.write('AgentBrake hook could not start (%r): call blocked (fail-closed). '\n"
    "                     'Repair the install, or run: agentbrake claude-code uninstall\\n' % (e,))\n"
    "    sys.exit(2)\n"
    "sys.exit(main(['claude-code', 'hook']))\n"
)


# -I (isolated mode): the hook runs with the project as its working directory,
# and `python -c` would otherwise put that directory first on sys.path — a
# repository shipping its own `agentbrake/` package could replace the hook
# with one that allows everything. -I also ignores PYTHONPATH and the user
# site directory, so install() checks that the hook still starts.
HOOK_ARGS = ["-I", "-c", BOOTSTRAP, HOOK_MARKER]


def hook_settings(python: str) -> Dict[str, Any]:
    """The ``hooks`` block for settings.json (exec form: no shell involved)."""
    handler: Dict[str, Any] = {
        "type": "command",
        "command": python,
        "args": list(HOOK_ARGS),
        "timeout": 10,
    }
    post = dict(handler, args=list(handler["args"]), **{"async": True})
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [handler]}],
        "PostToolUse": [{"matcher": "*", "hooks": [post]}],
        "PostToolUseFailure": [{"matcher": "*", "hooks": [dict(post)]}],
    }


def _is_ours(handler: Any) -> bool:
    return isinstance(handler, dict) and HOOK_MARKER in (handler.get("args") or [])


def _strip_ours(hooks: Dict[str, Any]) -> int:
    removed = 0
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if isinstance(group, dict) and isinstance(group.get("hooks"), list):
                kept = [h for h in group["hooks"] if not _is_ours(h)]
                removed += len(group["hooks"]) - len(kept)
                if not kept:
                    continue
                group = dict(group, hooks=kept)
            kept_groups.append(group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    return removed


def _read_settings(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return data


def _write_settings(path: Path, data: Dict[str, Any]) -> Optional[Path]:
    backup = None
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.agentbrake-backup-{stamp}")
        backup.write_bytes(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    _replace(tmp, path)
    return backup


def self_test(python: str) -> None:
    """Start the hook exactly as Claude Code will; raise if it cannot run.

    Installing a hook that cannot start would block every tool call (the
    bootstrap fails closed), so this runs first. The probe is an event the
    hook ignores, so it reads and writes nothing.
    """
    import subprocess

    probe = json.dumps({"hook_event_name": "SelfTest", "session_id": "self-test"}).encode()
    try:
        proc = subprocess.run([python, *HOOK_ARGS], input=probe, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError(f"cannot run the hook with {python}: {e}") from None
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise ValueError(
            f"the hook does not start with {python} (exit {proc.returncode}): {detail}. "
            "Install py-agentbrake into that interpreter (not with --user), or pass --python."
        )


def install(settings_path: Path, python: str, out: IO[str], check: bool = True) -> int:
    if check:
        self_test(python)
    data = _read_settings(settings_path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {settings_path} is not an object")
    _strip_ours(hooks)
    for event, groups in hook_settings(python).items():
        hooks.setdefault(event, []).extend(groups)
    backup = _write_settings(settings_path, data)
    out.write(f"AgentBrake hook installed in {settings_path}\n")
    if backup:
        out.write(f"  previous file saved as {backup}\n")
    out.write(f"  interpreter: {python}\n")
    if data.get("disableAllHooks"):
        out.write("  WARNING: this file sets disableAllHooks: true, so no hook runs.\n")
    out.write("Claude Code picks up the change automatically; new sessions are protected.\n")
    return 0


def uninstall(settings_path: Path, out: IO[str]) -> int:
    data = _read_settings(settings_path)
    hooks = data.get("hooks")
    removed = _strip_ours(hooks) if isinstance(hooks, dict) else 0
    if isinstance(hooks, dict) and not hooks:
        del data["hooks"]
    if removed:
        backup = _write_settings(settings_path, data)
        out.write(f"Removed {removed} AgentBrake hook entr{'y' if removed == 1 else 'ies'} "
                  f"from {settings_path} (backup: {backup})\n")
    else:
        out.write(f"No AgentBrake hook entries in {settings_path}\n")
    return 0


def _sessions(paths: Paths) -> List[Tuple[float, str]]:
    if not paths.home.exists():
        return []
    found = []
    for state in paths.home.glob("*.state.json"):
        found.append((state.stat().st_mtime, state.name[: -len(".state.json")]))
    for ledger in paths.home.glob("*.receipts.jsonl"):
        sid = ledger.name[: -len(".receipts.jsonl")]
        if not any(s == sid for _, s in found):
            found.append((ledger.stat().st_mtime, sid))
    return sorted(found, reverse=True)


def status(paths: Paths, out: IO[str]) -> int:
    disabled, until = disabled_until(paths)
    out.write(f"AgentBrake for Claude Code -- state directory: {paths.home}\n")
    if disabled:
        when = (datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M") if until else "re-enabled")
        out.write(f"  Hook: DISABLED (until {when}; `agentbrake claude-code enable` to turn it back on)\n")
    else:
        out.write("  Hook: enabled\n")
    try:
        policy = Policy.load(paths)
        out.write(f"  Policy: {'policy.json' if paths.policy.exists() else 'defaults'}, "
                  f"mode={policy.raw['mode']}, digest {policy.digest[:19]}...\n")
    except HookError as e:
        out.write(f"  Policy: INVALID -- {e}\n")
    if paths.key.exists():
        signer = signing.Ed25519Signer.from_pem_file(str(paths.key))
        out.write(f"  Signing key: {signer.key_id} (public {signer.public_key_hex()})\n")
    sessions = _sessions(paths)
    if not sessions:
        out.write("  No session recorded yet.\n")
        return 0
    out.write("  Sessions (most recent first):\n")
    for mtime, sid in sessions[:10]:
        line = f"    {sid}  {datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')}"
        try:
            state = SessionState.from_dict(
                json.loads(paths.state(sid).read_text(encoding="utf-8")), sid)
            line += f"  calls={state.total_calls}  taint={_taint_summary(state.run)}"
        except FileNotFoundError:
            line += "  (state reset)"
        except Exception as e:  # noqa: BLE001
            line += f"  STATE UNREADABLE ({type(e).__name__})"
        rows = receipts.JsonlLedger(str(paths.receipts(sid))).all() if paths.receipts(sid).exists() else []
        out.write(f"{line}  receipts={len(rows)}\n")
    return 0


def reset(paths: Paths, session: Optional[str], all_sessions: bool, out: IO[str]) -> int:
    sessions = [sid for _, sid in _sessions(paths)]
    if all_sessions:
        targets = sessions
    elif session:
        targets = [session]
    else:
        targets = sessions[:1]
    if not targets:
        out.write("No session to reset.\n")
        return 0
    for sid in targets:
        if not _SESSION_RE.fullmatch(sid):
            raise ValueError(f"malformed session id {sid!r}")
        with FileLock(paths.lock(sid), 5.0):
            state_path = paths.state(sid)
            context: Dict[str, Any] = {"by": "user", "command": "agentbrake claude-code reset"}
            try:
                state = SessionState.from_dict(json.loads(state_path.read_text(encoding="utf-8")), sid)
                context.update(cleared_taints=[t.label for t in state.run.taints],
                               calls=state.total_calls)
            except FileNotFoundError:
                context["state"] = "absent"
            except Exception as e:  # noqa: BLE001 — resetting is how a corrupt state is fixed
                context["state"] = f"unreadable ({type(e).__name__})"
            with _hook_signer(paths):
                row = receipts.mint_detector_receipt(
                    receipts.JsonlLedger(str(paths.receipts(sid))), detector_kind="session_reset",
                    run_id=sid, tool="(user)", context=context, decision="reset",
                )
            if state_path.exists():
                state_path.unlink()
        out.write(f"Session {sid}: taint, history and counters cleared "
                  f"(receipt #{row['seq']} records the reset).\n")
    return 0


def disable(paths: Paths, minutes: Optional[float], out: IO[str]) -> int:
    paths.home.mkdir(parents=True, exist_ok=True)
    until = time.time() + minutes * 60 if minutes else None
    paths.disabled.write_text(json.dumps({"until": until, "set_at": _now()}), encoding="utf-8")
    if until:
        out.write(f"AgentBrake hook DISABLED until {datetime.fromtimestamp(until):%H:%M} "
                  "(Claude Code calls go through unchecked and unrecorded).\n")
    else:
        out.write("AgentBrake hook DISABLED until `agentbrake claude-code enable` "
                  "(Claude Code calls go through unchecked and unrecorded).\n")
    return 0


def enable(paths: Paths, out: IO[str]) -> int:
    if paths.disabled.exists():
        paths.disabled.unlink()
    out.write("AgentBrake hook enabled.\n")
    return 0


def export_session(paths: Paths, session: Optional[str], target: str, out: IO[str]) -> int:
    from .. import export as export_mod

    sid = session or next((s for _, s in _sessions(paths)), None)
    if sid is None or not paths.receipts(sid).exists():
        out.write("No receipts to export.\n")
        return 1
    signer = load_or_create_signer(paths)
    bundle = export_mod.build_export(export_mod.rows_from_jsonl(str(paths.receipts(sid))), signer=signer)
    written = export_mod.write_export(bundle, target)
    out.write(f"Exported {len(bundle['entries'])} receipt(s) of session {sid} to {written}\n")
    out.write("Verify offline with:\n")
    out.write(f"  agentbrake verify {written} --public-key {signer.public_key_hex()}\n")
    return 0


def iter_receipts(paths: Paths, session_id: str) -> Iterator[Dict[str, Any]]:
    """Receipt rows of one session, oldest first (empty if none)."""
    if paths.receipts(session_id).exists():
        yield from receipts.JsonlLedger(str(paths.receipts(session_id))).all()
