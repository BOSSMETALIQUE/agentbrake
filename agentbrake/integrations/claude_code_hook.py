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
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import IO, Any, Dict, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .. import receipts, signing
from ..detectors import BudgetDetector, LoopDetector, RetryStormDetector
from ..flow import ArgExemption, FlowPolicy, FlowRuleDetector, _normalize_domain, normalize_address
from ..server import attest
from ..types import InterruptReason, RunState, TaintMark, ToolCall

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

HOME_ENV = "AGENTBRAKE_CC_HOME"
# Recognizes this hook's entries in a settings.json, so install / uninstall
# touch only what they wrote.
HOOK_MARKER = "agentbrake-claude-code-hook"
# The two kinds of taint a session can carry. UNTRUSTED: the session has read
# content an attacker could control (a web page, a search result, an MCP read).
# PRIVATE: the session has read a secret (an .env, a key file, `gh auth token`).
# EGRESS: a call that can send data off the machine.
UNTRUSTED = "untrusted"
PRIVATE = "private"
EGRESS = "egress"
TAINT = UNTRUSTED  # backwards-compatible alias for the taint-strict path
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
    # "trifecta" (default): only interrupt when private data AND untrusted
    #   content are both in the session and a call sends data to a destination
    #   that is not allow-listed. One leg alone is allowed (and recorded).
    # "ask"/"taint-strict": the pre-0.4 behaviour — any untrusted read then any
    #   egress asks the user. "strict": the same, but denies instead of asking.
    "mode": "trifecta",
    # Taint the session UNTRUSTED when one of these is *attempted*. Globs match
    # the full tool name; every MCP tool returns outside content by default.
    "untrusted_sources": ["WebFetch", "WebSearch", "mcp__*"],
    # Reading one of these file paths (Read/Grep/Glob/Edit/NotebookEdit) taints
    # the session PRIVATE. Matched against the full path and its basename.
    "private_file_globs": [
        ".env", ".env.*", "*.pem", "*.key", "id_rsa", "id_rsa.*",
        "id_ed25519", "id_ed25519.*", "*.kdbx", ".npmrc", ".pypirc", ".netrc",
        ".git-credentials", "*/.ssh/*", "*/.aws/credentials",
        "*/.config/gcloud/*", "*/.claude/*", "*.claude.json", "*/.agentbrake/*",
    ],
    # A shell command matching one of these (case-insensitive) taints the
    # session PRIVATE: it reveals secrets (env dump, credential read, key cat).
    "private_command_patterns": [
        r"(?:^|[;&|]\s*)(?:env|printenv)\s*(?:$|[|;&])",
        r"\bge?t?-?childitem\s+env:|\b(?:ls|dir|gci|gi|get-item)\s+env:",
        r"\bgit\s+config\s+(?:--global\s+)?(?:--list|-l)\b",
        r"\bgh\s+auth\s+token\b",
        r"\baws\s+configure\s+(?:export-credentials|get)\b",
        r"\bsecurity\s+find-(?:generic|internet)-password\b",
        r"\b(?:cat|type|more|less|head|tail|get-content|gc)\b[^;&|\n]*"
        r"(?:\.env\b|\.pem\b|\.key\b|id_rsa|id_ed25519|[\\/]\.ssh[\\/]"
        r"|[\\/]\.aws[\\/]credentials|\.npmrc|\.pypirc|\.netrc"
        r"|\.git-credentials|\.kdbx)",
    ],
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
    # Hosts WebFetch may reach from a tainted session (taint-strict modes only):
    # "docs.python.org", or "*.example.com" for subdomains only.
    "webfetch_allowed_domains": [],
    # Trifecta mode: destinations treated as "allowed" by the decision matrix.
    # A full trifecta into an allow-listed host is downgraded from deny to ask;
    # it is never silently allowed. Kept deliberately short, and limited to
    # package registries and the user's own VCS host. Multi-tenant drop boxes
    # that double as exfil channels (gist.github.com, pastebin.com,
    # huggingface.co, transfer.sh, requestbin, ...) are intentionally absent:
    # an attacker can read their own logs there. Add your own at your own risk.
    "egress_allowed_domains": [
        "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
        "crates.io", "static.crates.io", "github.com", "api.github.com",
        "raw.githubusercontent.com", "codeload.github.com",
    ],
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


def _host_list(value: Any, where: str) -> List[str]:
    hosts = [d.strip().lower() for d in _str_list(value, where)]
    for host in hosts:
        if not _HOST_RE.fullmatch(host):
            raise HookError(
                f"policy.json: {where} entry {host!r} is not a host such as "
                "'docs.python.org' or '*.example.com'"
            )
    return hosts


def _compile_patterns(value: Any, where: str) -> List["re.Pattern[str]"]:
    compiled = []
    for pat in _str_list(value, where):
        try:
            compiled.append(re.compile(pat, re.I))
        except re.error as e:
            raise HookError(f"policy.json: {where} has an invalid regex {pat!r}: {e}") from None
    return compiled


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

        # "taint-strict" is the name the docs give the pre-0.4 behaviour; it is
        # an alias of "ask". "trifecta" is the new default.
        mode = merged["mode"]
        if mode == "taint-strict":
            mode = "ask"
        if mode not in ("trifecta", "ask", "strict"):
            raise HookError(
                "policy.json: mode must be 'trifecta', 'taint-strict' (alias 'ask') or 'strict'"
            )
        self.mode = mode
        # In trifecta mode a full trifecta into an unlisted host is denied with
        # no prompt; everything else that reaches the user is an ask.
        self.flow_decision = "deny" if mode == "strict" else "ask"
        self.untrusted_sources = _str_list(merged["untrusted_sources"], "untrusted_sources")
        if not self.untrusted_sources:
            raise HookError(
                "policy.json: untrusted_sources is empty, so nothing could ever taint a "
                "session; use `agentbrake claude-code disable` to switch the hook off instead"
            )
        self.private_file_globs = _str_list(merged["private_file_globs"], "private_file_globs")
        self.private_command_patterns = _compile_patterns(
            merged["private_command_patterns"], "private_command_patterns")
        self.shell_tools = _str_list(merged["shell_tools"], "shell_tools")
        self.mcp_sinks = _str_list(merged["mcp_sinks"], "mcp_sinks")
        self.mcp_not_sinks = _str_list(merged["mcp_not_sinks"], "mcp_not_sinks")
        self.webfetch_allowed_domains = _host_list(
            merged["webfetch_allowed_domains"], "webfetch_allowed_domains")
        self.egress_allowed_domains = _host_list(
            merged["egress_allowed_domains"], "egress_allowed_domains")

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


# -- private data: reading a secret file, or a command that reveals one --------

# File tools whose arguments name a file whose *contents* reach the model.
_READ_LIKE_TOOLS = {
    "Read": ("file_path",),
    "Edit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Grep": ("path", "glob"),
    "Glob": ("path", "pattern"),
}
# Short, path-free phrases for the glob that matched. Never echoes the path: a
# full path can itself carry private detail (a client name in a directory).
_PRIVATE_PHRASES: Tuple[Tuple[str, str], ...] = (
    (".env", "a .env file"), (".env.*", "a .env file"),
    ("id_rsa", "an SSH private key"), ("id_rsa.*", "an SSH private key"),
    ("id_ed25519", "an SSH private key"), ("id_ed25519.*", "an SSH private key"),
    ("*.pem", "a private key"), ("*.key", "a private key"),
    ("*/.ssh/*", "an SSH file"), ("*/.aws/credentials", "AWS credentials"),
    ("*/.config/gcloud/*", "gcloud credentials"), ("*.kdbx", "a password database"),
    (".npmrc", "an npm credentials file"), (".pypirc", "a PyPI credentials file"),
    (".netrc", "a .netrc credentials file"), (".git-credentials", "stored git credentials"),
    ("*/.claude/*", "a Claude config file"), ("*.claude.json", "a Claude config file"),
    ("*/.agentbrake/*", "an AgentBrake file"),
)


def _norm_posix(path: str) -> str:
    return os.path.expanduser(path).replace("\\", "/").lower()


def _phrase_for_glob(glob: str) -> str:
    g = glob.lower()
    for pat, phrase in _PRIVATE_PHRASES:
        if pat.lower() == g:
            return phrase
    return "a sensitive file"


def _private_file_phrase(path: str, globs: Sequence[str]) -> Optional[str]:
    full = _norm_posix(path)
    base = full.rsplit("/", 1)[-1]
    for glob in globs:
        g = glob.lower()
        if fnmatch.fnmatchcase(base, g) or fnmatch.fnmatchcase(full, g):
            return _phrase_for_glob(glob)
    return None


# -- reading a sensitive file through ANY shell command ------------------------
#
# The taint must not depend on the command verb: `awk ... .env`, `grep x .env`,
# `python -c "open('.env')"` and `cp .env /tmp` all expose the file, the same as
# `cat .env`. So we look for a sensitive *path* anywhere in the command text,
# whatever runs it. This is a text heuristic over the command string, not a
# shell parser (see the README): it can miss and it can over-flag. Because the
# "private" leg alone never prompts (only the full trifecta does), we err toward
# flagging.

# Commands that print their arguments without opening a file named in them: a
# sensitive-looking token here is text, not a read. (A real read hidden in a
# subshell is still caught — the subshell is a separate segment.)
_PRINTERS = frozenset({
    "echo", "printf", "print", "write-output", "write-host", "write-error", "@echo",
})
# Commands that stream a file's *contents*. For these, a path we cannot resolve
# (an unexpanded variable, a subshell) is treated as sensitive — fail-closed.
_CONTENT_READERS = frozenset({
    "cat", "tac", "nl", "type", "more", "less", "head", "tail", "awk", "gawk", "mawk",
    "sed", "grep", "egrep", "fgrep", "rg", "ag", "ack", "select-string", "sls",
    "get-content", "gc", "cut", "strings", "xxd", "od", "hexdump", "base64", "source",
    ".", "wc", "sort", "uniq", "tr", "paste", "dd", "readlink", "realpath",
})
_HOME = os.path.expanduser("~").replace("\\", "/")
_HOME_VARS = re.compile(r"\$\{?HOME\}?|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%|%HOME(?:PATH)?%", re.I)
_UNRESOLVED = re.compile(r"\$\w|\$\{|\$\(|`|%[A-Za-z_][A-Za-z0-9_]*%")
# A path-ish fragment inside a larger token (e.g. inside `open('.env')`).
_PATHISH = re.compile(r"(?:~|\$\{?\w+\}?|%[A-Za-z_]+%|\.{0,2}[\\/]|\.?\w)[\w.$%{}~@:\\/*?-]*")
# Command separators only — NOT braces/parens, which appear in awk/jq programs
# and in PowerShell script blocks and must not cut a command from its file arg.
_PRIV_SEG = re.compile(r"\|\||&&|\$\(|[|;&\n`]")


def _expand_pathish(token: str) -> Tuple[str, bool]:
    """Expand ~ and the common home variables. Returns (expanded, resolved)."""
    t = token
    if t[:1] == "~":
        t = _HOME + t[1:]
    t = _HOME_VARS.sub(_HOME, t)
    return t, (_UNRESOLVED.search(t) is None)


def _private_reps(globs: Sequence[str]) -> List[Tuple[str, str]]:
    """Concrete example names for basename globs, so a glob *token* like `.e*`
    can be matched (``fnmatch(".env", ".e*")``). Returns (example, glob)."""
    reps = []
    for g in globs:
        if "/" in g:
            continue
        reps.append((g.replace("*", "x").replace("?", "x"), g))
    return reps


def _is_private_path(token: str, globs: Sequence[str], reps: List[Tuple[str, str]]) -> Optional[str]:
    norm = token.replace("\\", "/").strip().strip("'\"").lower()
    while norm.startswith("./"):
        norm = norm[2:]
    if not norm:
        return None
    base = norm.rsplit("/", 1)[-1]
    for g in globs:
        gl = g.lower()
        if fnmatch.fnmatchcase(base, gl) or fnmatch.fnmatchcase(norm, gl):
            return g
    if "*" in token or "?" in token:  # the token is itself a glob (cat .e*)
        for example, g in reps:
            if fnmatch.fnmatchcase(example, base):
                return g
    return None


def _candidate_fragments(word: str) -> List[Tuple[str, bool]]:
    """Path candidates in one shell word: the token itself and any path-ish
    fragment inside it (for inline code / glued redirections)."""
    s = word.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]
    out: List[Tuple[str, bool]] = []
    t = s
    while t[:1] == "<":
        t = t[1:]
    if t[:1] == ">":  # an output-redirect target is a write, not a read
        t = ""
    if t:
        out.append(_expand_pathish(t))
    for m in _PATHISH.finditer(s):
        frag = m.group(0)
        if frag and frag != t:
            out.append(_expand_pathish(frag))
    return out


def _command_private_reason(command: str, globs: Sequence[str]) -> Optional[str]:
    """A sensitive file read by any command in ``command``, or None."""
    reps = _private_reps(globs)
    undetermined = False
    for segment in _PRIV_SEG.split(command):
        words = _WORD_RE.findall(segment)
        if not words:
            continue
        idx = 0
        while idx < len(words):
            w = words[idx]
            bare = _program_name(w)
            if _ASSIGNMENT_RE.match(w) or bare in _WRAPPERS:
                idx += 1
                continue
            if w.startswith("-") or re.fullmatch(r"\d+[smhd]?", w):
                idx += 1
                continue
            break
        program = _program_name(words[idx]) if idx < len(words) else ""
        if program in _PRINTERS:
            continue
        is_reader = program in _CONTENT_READERS
        for w in words:
            for cand, resolved in _candidate_fragments(w):
                hit = _is_private_path(cand, globs, reps)
                if hit:
                    return _phrase_for_glob(hit)
                if is_reader and not resolved and _UNRESOLVED.search(w):
                    undetermined = True
    if undetermined:
        return "a file whose path could not be determined"
    return None


def _private_reason(policy: "Policy", tool: str, tool_input: Dict[str, Any]) -> Optional[str]:
    """A short, path-free reason this call exposes private data, or None."""
    keys = _READ_LIKE_TOOLS.get(tool)
    if keys:
        for key in keys:
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                phrase = _private_file_phrase(value, policy.private_file_globs)
                if phrase:
                    return phrase
    if tool in policy.shell_tools:
        command = tool_input.get("command")
        if isinstance(command, str):
            # A command that reveals secrets without naming a file (env dump,
            # `gh auth token`, `git config --list`): the configurable patterns.
            for pat in policy.private_command_patterns:
                if pat.search(command):
                    return "credentials from the shell"
            # A command that reads a sensitive file, whatever the verb.
            phrase = _command_private_reason(command, policy.private_file_globs)
            if phrase:
                return phrase
    return None


# -- secrets that appear literally in an outbound call's arguments -------------

_SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("a GitHub token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("a Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("a private key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("a JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("a Stripe secret key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
)
# Generic high-entropy fallback: a long token with upper, lower and digits.
_GENERIC_SECRET = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,}(?![A-Za-z0-9+/=_-])")


def _looks_entropic(token: str) -> bool:
    return (any(c.isupper() for c in token) and any(c.islower() for c in token)
            and any(c.isdigit() for c in token))


def secret_fingerprint(text: str) -> Optional[Dict[str, str]]:
    """``{"kind": ..., "fp": "sha256:..."}`` for a secret-looking token, or None.

    Only the SHA-256 fingerprint of the matched value is returned, never the
    value itself, so it is safe to put in state, receipts and messages. This is
    pattern matching, not proof: it can miss a secret and flag a non-secret.
    """
    for kind, pattern in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            return {"kind": kind, "fp": _value_fp(m.group(0))}
    for m in _GENERIC_SECRET.finditer(text):
        token = m.group(0)
        if _looks_entropic(token):
            return {"kind": "a high-entropy string", "fp": _value_fp(token)}
    return None


def _value_fp(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _shell_url_host(command: Any) -> Optional[str]:
    """The host of the first URL in a shell command, if one is present."""
    if not isinstance(command, str):
        return None
    m = _URL_RE.search(command)
    if not m:
        return None
    tail = command[m.start():]
    end = len(tail)
    for i, ch in enumerate(tail):
        if ch.isspace() or ch in "'\"`|;&><()":
            end = i
            break
    return _host_of(tail[:end])


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


@dataclass(frozen=True)
class TriRoles:
    """What the trifecta rule needs to know about one call.

    ``untrusted`` / ``private_reason`` are the two taint legs this call would
    introduce. ``egress`` (a logical sink name) is set only when the call can
    send data off the machine — for WebFetch, only when the host is *not*
    allow-listed, since a fetch to an allowed host is not treated as an exit.
    ``host`` is never written to a receipt; it is for the message only.
    """

    untrusted: bool
    private_reason: Optional[str]
    egress: Optional[str] = None
    egress_why: Optional[str] = None
    host: Optional[str] = None
    host_determinable: bool = False
    host_allowed: bool = False
    secret: Optional[Dict[str, str]] = None


def _egress_secret(tool_input: Dict[str, Any]) -> Optional[Dict[str, str]]:
    for value in tool_input.values():
        if isinstance(value, str) and value:
            hit = secret_fingerprint(value)
            if hit:
                return hit
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    hit = secret_fingerprint(item)
                    if hit:
                        return hit
    return None


def classify_trifecta(policy: Policy, tool: str, tool_input: Dict[str, Any]) -> TriRoles:
    """Trifecta roles: the two taint legs plus the outbound role of a call."""
    untrusted = _matches(tool, policy.untrusted_sources)
    private_reason = _private_reason(policy, tool, tool_input)
    allowed_domains = [*policy.egress_allowed_domains, *policy.webfetch_allowed_domains]

    def done(**kw: Any) -> TriRoles:
        egress = kw.get("egress")
        secret = _egress_secret(tool_input) if egress else None
        return TriRoles(untrusted, private_reason, secret=secret, **kw)

    if tool in policy.shell_tools:
        if tool == "Monitor" and "ws" in tool_input:
            host = _host_of((tool_input.get("ws") or {}).get("url")
                            if isinstance(tool_input.get("ws"), dict) else None)
            return done(egress=f"{tool}(network)", egress_why="a WebSocket connection to the network",
                        host=host, host_determinable=host is not None,
                        host_allowed=_host_allowed(host, allowed_domains))
        reason = shell_egress_reason(tool_input.get("command"))
        if reason is None:
            return done()
        host = _shell_url_host(tool_input.get("command"))
        return done(egress=f"{tool}(network)", egress_why=reason, host=host,
                    host_determinable=host is not None,
                    host_allowed=_host_allowed(host, allowed_domains))
    if tool == "WebFetch":
        host = _host_of(tool_input.get("url"))
        if _host_allowed(host, allowed_domains):
            return done()  # fetch to an allow-listed host is not treated as an exit
        return done(egress="WebFetch(url)", egress_why="the web address is not on your allow-list",
                    host=host, host_determinable=host is not None, host_allowed=False)
    if tool.startswith("mcp__") and (
        tool in policy.recipients
        or (_matches(tool, policy.mcp_sinks) and not _matches(tool, policy.mcp_not_sinks))
    ):
        determinable = tool in policy.recipients
        allowed = False
        if determinable:
            exemption = ArgExemption(
                tool=_sink_name(tool),
                fields=tuple(policy.recipients[tool].get("fields", ())),
                values=tuple(sorted({normalize_address(v)
                                     for v in policy.recipients[tool].get("values", ())})),
                domains=tuple(sorted({_normalize_domain(d)
                                      for d in policy.recipients[tool].get("domains", ())})),
                other_fields=tuple(policy.recipients[tool].get("other_fields", ())),
            )
            allowed = bool(exemption.evaluate(tool_input)[0])
        return done(egress=_sink_name(tool), egress_why="an MCP tool that can send data out",
                    host_determinable=determinable, host_allowed=allowed)
    return done()


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


# -- shared between the two decision modes ------------------------------------

def _detector_trips(policy: Policy, state: SessionState, tool: str,
                    history_call: ToolCall) -> List[Trip]:
    """Loop / retry-storm / budget trips — identical in every mode."""
    trips: List[Trip] = []
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
    if RetryStormDetector(policy.storm_max, policy.storm_window).check(failures, history_call) is not None:
        failed = sum(1 for c in failures.calls if c.name == tool)
        trips.append(Trip(
            "retry_storm", policy.storm_decision,
            f"{tool} failed {failed} times in the last {policy.storm_window} calls (retry storm)",
            context={"failures": failed, "window": policy.storm_window},
        ))
    if BudgetDetector(policy.max_calls * COST_PER_CALL_USD).check(state.run, history_call) is not None:
        trips.append(Trip(
            "budget", policy.budget_decision,
            f"this session reached its budget of {policy.max_calls} tool calls",
            context={"call_count": state.total_calls, "max_calls": policy.max_calls},
        ))
    return trips


def _apply_taints(state: SessionState, pairs: Sequence[Tuple[str, str]]) -> None:
    """Record taint labels introduced by this call (dedup by label, on attempt)."""
    active = state.run.taint_labels()
    for label, source_tool in pairs:
        if label not in active:
            state.run.taints.append(TaintMark(
                label=label, source_tool=source_tool, call_index=state.total_calls - 1))
            active.add(label)


def _record_attempt(state: SessionState, tool: str, tool_use_id: str, history_call: ToolCall,
                    ask_record: Optional[Dict[str, Any]], taints: Sequence[Tuple[str, str]]) -> None:
    """Commit a call that will run (or is put to the user): history, taint, pending."""
    state.run.append(history_call)
    state.total_calls += 1
    _apply_taints(state, taints)
    state.pending[tool_use_id] = {"index": state.total_calls - 1, "tool": tool, "ask": ask_record}


def _finalize(ctx: _Context, tool: str, tool_use_id: str, trips: List[Trip],
              sink_call: Optional[ToolCall], ask_sink: Optional[str],
              history_call: ToolCall, taints: Sequence[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
    """Pick the decision (deny first, else ask), mint it, and record the attempt."""
    decision: Optional[str] = None
    output: Optional[Dict[str, Any]] = None
    ask_record: Optional[Dict[str, Any]] = None
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
                ask_record.update(sink=ask_sink, flow=receipts.flow_for_receipt(chosen.flow))
    if decision != "deny":
        _record_attempt(ctx.state, tool, tool_use_id, history_call, ask_record, taints)
    return output


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
    """Dispatch a PreToolUse decision to the mode the policy selects."""
    if ctx.policy.mode == "trifecta":
        return _decide_pre_trifecta(ctx, event)
    return _decide_pre_taint_strict(ctx, event)


def _decide_pre_taint_strict(ctx: _Context, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The pre-0.4 rule: any untrusted read, then any egress, asks (or denies)."""
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

    history_call = ToolCall(name=tool, args=compact_args(tool_input), cost_usd=COST_PER_CALL_USD)
    trips += _detector_trips(policy, state, tool, history_call)

    if not trips and allowed_flow is not None:
        assert sink_call is not None
        with _hook_signer(ctx.paths):
            receipts.mint_flow_allow_receipt(
                ctx.ledger, run_state=state.run, sink_call=sink_call,
                flow=receipts.flow_for_receipt(allowed_flow), policy_digest_value=policy.digest,
            )
    taints = [(UNTRUSTED, tool)] if roles.source else []
    return _finalize(ctx, tool, tool_use_id, trips, sink_call, roles.sink, history_call, taints)


def _trifecta_provenance(state: SessionState, label: str, own: Optional[str]) -> Optional[str]:
    """How this session acquired ``label`` — a prior taint, else this call's own."""
    for t in state.run.taints:
        if t.label == label:
            return f"{t.source_tool} (call #{t.call_index + 1})"
    if own is not None:
        return f"{own} (this call)"
    return None


def _untrusted_phrase(tool: str) -> str:
    if tool == "WebFetch":
        return "a web page"
    if tool == "WebSearch":
        return "web search results"
    if tool.startswith("mcp__"):
        return "external tool output"
    return "untrusted content"


def _decide_pre_trifecta(ctx: _Context, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The default rule: interrupt only on the full trifecta into an unlisted host."""
    tool: str = event["tool_name"]
    tool_input: Dict[str, Any] = event["tool_input"]
    tool_use_id = str(event.get("tool_use_id") or f"call-{ctx.state.total_calls}")
    policy, state = ctx.policy, ctx.state
    roles = classify_trifecta(policy, tool, tool_input)
    trips: List[Trip] = []

    protected = protection_check(ctx.paths, tool, tool_input)
    if protected is not None:
        trips.append(protected)

    sink_call = ToolCall(name=roles.egress, args=tool_input) if roles.egress else None
    observe_flow: Optional[Dict[str, Any]] = None
    if roles.egress is not None:
        active = state.run.taint_labels()
        # Fold this call's own PRIVATE leg (a `cat .env | curl` reads and sends
        # in one breath), but NOT its own untrusted leg: for a WebFetch the
        # untrusted content is arriving, not leaving, so counting it would deny
        # the fetch itself. Untrusted is judged on what the session read before.
        has_priv = PRIVATE in active or roles.private_reason is not None
        has_unt = UNTRUSTED in active
        priv_src = _trifecta_provenance(state, PRIVATE, roles.private_reason)
        unt_src = _trifecta_provenance(
            state, UNTRUSTED, _untrusted_phrase(tool) if roles.untrusted else None)
        flow = _trifecta_flow_payload(roles, has_priv, has_unt, priv_src, unt_src)

        if has_priv and has_unt:
            # Determinable unlisted host => clearly external => deny outright.
            # Allow-listed or undeterminable => ask.
            decision = "deny" if (roles.host_determinable and not roles.host_allowed) else "ask"
            msg = (f"{_trifecta_sentence(tool, roles)} The session read {priv_src} and {unt_src}. "
                   "If that page carried a hidden instruction, this is how your data would leak")
            trips.append(Trip("flow", decision, msg, flow=flow))
        elif roles.secret is not None:
            # A secret value sits in an outbound call's arguments, taint or not.
            flow["decision_basis"] = "secret_in_args"
            trips.append(Trip(
                "flow", "ask",
                f"{_trifecta_sentence(tool, roles)} One of its arguments looks like "
                f"{roles.secret['kind']} (fingerprint {roles.secret['fp']}), so it may be a secret "
                "leaving the machine",
                flow=flow))
        elif has_priv or has_unt:
            observe_flow = flow  # one leg only: allow, but keep a record

    history_call = ToolCall(name=tool, args=compact_args(tool_input), cost_usd=COST_PER_CALL_USD)
    trips += _detector_trips(policy, state, tool, history_call)

    if not trips and observe_flow is not None:
        assert sink_call is not None
        with _hook_signer(ctx.paths):
            receipts.mint_flow_observe_receipt(
                ctx.ledger, run_state=state.run, sink_call=sink_call,
                flow=observe_flow, policy_digest_value=policy.digest)

    taints: List[Tuple[str, str]] = []
    if roles.untrusted:
        taints.append((UNTRUSTED, _untrusted_phrase(tool)))
    if roles.private_reason:
        taints.append((PRIVATE, roles.private_reason))
    return _finalize(ctx, tool, tool_use_id, trips, sink_call, roles.egress, history_call, taints)


def _trifecta_sentence(tool: str, roles: TriRoles) -> str:
    """The 'what' clause: which tool and where, in plain words (no jargon)."""
    if tool == "WebFetch":
        return f"This web fetch to {roles.host or 'an external site'} can carry data off the machine."
    if tool == "Monitor":
        return "This Monitor WebSocket connection can carry data off the machine."
    if tool.startswith("mcp__"):
        return f"This {tool} call can send data out."
    dest = f" to {roles.host}" if roles.host else ""
    return f"This command ({roles.egress_why}){dest} can send data off the machine."


def _trifecta_flow_payload(roles: TriRoles, has_priv: bool, has_unt: bool,
                           priv_src: Optional[str], unt_src: Optional[str]) -> Dict[str, Any]:
    """Receipt payload for a trifecta decision. Never contains the host or a secret value."""
    payload: Dict[str, Any] = {
        "sink": roles.egress,
        "sink_category": EGRESS,
        "sink_reason": roles.egress_why,
        "decision_basis": "trifecta",
        "private_data": has_priv,
        "untrusted_content": has_unt,
        "destination_determinable": roles.host_determinable,
        "destination_allowed": roles.host_allowed,
        "provenance": {"private": priv_src, "untrusted": unt_src},
    }
    if roles.secret is not None:
        payload["secret_argument"] = dict(roles.secret)  # kind + sha256 fingerprint only
    return payload


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
            # Bind the approval to the ask it answers, so `stats` can pair them.
            flow = {**(ask.get("flow") or {}), "ask_receipt_seq": ask.get("seq")}
            receipts.mint_flow_override_receipt(
                ctx.ledger, run_state=ctx.state.run,
                sink_call=ToolCall(name=ask["sink"], args=tool_input),
                flow=flow, interrupt_id=str(tool_use_id),
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


def print_settings(python: Optional[str], out: IO[str]) -> int:
    """Print the hooks block to paste into a settings.json (no provisioning)."""
    out.write(json.dumps({"hooks": hook_settings(python or sys.executable)}, indent=2))
    out.write("\n")
    return 0


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


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _looks_isolated(python: str) -> bool:
    """True if ``python`` is already a per-application interpreter we can pin to.

    A hook must keep running whatever the user's shell does later, so it has to
    point at an interpreter that won't move or change under it. pipx and
    ``uv tool`` give each app its own venv at a stable path; a plain
    ``pip install`` into the active/project/system interpreter does not.
    """
    low = os.path.normcase(python).replace("\\", "/")
    return any(mark in low for mark in ("/pipx/", "/uv/tools/", "/.agentbrake/"))


def bootstrap_dedicated_venv(venv_dir: Path, out: IO[str]) -> Path:
    """Create ``venv_dir`` (if absent) and install py-agentbrake into it.

    The install source is ``AGENTBRAKE_INSTALL_SPEC`` when set (a wheel path, so
    tests and offline installs work), otherwise ``py-agentbrake==<version>``
    from PyPI. Returns the venv's python. Raises ValueError on failure.
    """
    import subprocess

    from .. import __version__

    python = _venv_python(venv_dir)
    if not python.exists():
        out.write(f"  creating a dedicated environment at {venv_dir} ...\n")
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)],
                           capture_output=True, check=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            raise ValueError(f"could not create a virtualenv at {venv_dir}: {e}") from None
    spec = os.environ.get("AGENTBRAKE_INSTALL_SPEC") or f"py-agentbrake=={__version__}"
    try:
        probe = subprocess.run([str(python), "-I", "-c", "import agentbrake"],
                               capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise ValueError(f"the new environment's python does not run: {e}") from None
    if probe.returncode != 0:
        out.write(f"  installing {spec} ...\n")
        try:
            done = subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                                   spec], capture_output=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as e:
            raise ValueError(f"could not install into {venv_dir}: {e}") from None
        if done.returncode != 0:
            raise ValueError(
                f"could not install {spec} into {venv_dir}:\n"
                f"{done.stderr.decode('utf-8', 'replace').strip()}")
    return python


def resolve_hook_python(python: Optional[str], out: IO[str], *,
                        venv_dir: Optional[Path] = None, dedicated: bool = True) -> str:
    """Pick the interpreter the hook will run with, provisioning one if needed."""
    if python:
        return python
    if not dedicated:
        return sys.executable
    if _looks_isolated(sys.executable):
        return sys.executable  # already pipx / uv tool / our own venv
    target = venv_dir or (Path.home() / ".agentbrake" / "venv")
    return str(bootstrap_dedicated_venv(target, out))


def install(settings_path: Path, python: Optional[str], out: IO[str], check: bool = True,
            *, venv_dir: Optional[Path] = None, dedicated: bool = True) -> int:
    resolved = resolve_hook_python(python, out, venv_dir=venv_dir, dedicated=dedicated)
    if check:
        self_test(resolved)
    data = _read_settings(settings_path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {settings_path} is not an object")
    _strip_ours(hooks)
    for event, groups in hook_settings(resolved).items():
        hooks.setdefault(event, []).extend(groups)
    backup = _write_settings(settings_path, data)
    out.write(f"AgentBrake hook installed in {settings_path}\n")
    if backup:
        out.write(f"  previous file saved as {backup}\n")
    out.write(f"  interpreter: {resolved}\n")
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


# ---------------------------------------------------------------------------
# stats: measure the user's own click-through behaviour, entirely locally
# ---------------------------------------------------------------------------

def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _ask_rule(att: Dict[str, Any]) -> str:
    """A short label for *why* an ask fired, for the 'top rules' list."""
    kind = att.get("kind")
    if kind == "flow_ask":
        basis = (att.get("flow") or {}).get("decision_basis")
        if basis == "secret_in_args":
            return "secret-looking value in an outbound command"
        return "private data + untrusted content heading out (trifecta)"
    if kind == "tamper":
        return "a call touching AgentBrake or Claude Code's own config"
    labels = {"loop": "a tool call repeating in a loop",
              "retry_storm": "a tool failing over and over (retry storm)",
              "budget": "the session's tool-call budget"}
    return labels.get(str(kind), str(kind))


def stats(paths: Paths, out: IO[str], days: Optional[int] = None) -> int:
    """Summarise local receipts: how often the hook interrupts, and how fast
    the user approves. Reads only local files; sends nothing anywhere."""
    cutoff = None
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    per_day: Dict[str, Dict[str, int]] = {}
    asks: Dict[Tuple[str, int], Dict[str, Any]] = {}      # (sid, seq) -> ask row
    approvals: List[Tuple[str, int, datetime]] = []        # (sid, ask_seq, approved_at)
    totals = {"deny": 0, "ask": 0, "observe": 0, "allow": 0}
    rule_counts: Dict[str, int] = {}
    n_sessions = 0

    for _, sid in _sessions(paths):
        if not paths.receipts(sid).exists():
            continue
        n_sessions += 1
        for row in receipts.JsonlLedger(str(paths.receipts(sid))).all():
            att = row.get("attestation", {})
            ts = _parse_ts(att.get("blocked_at"))
            if cutoff is not None and (ts is None or ts < cutoff):
                continue
            decision = att.get("decision")
            day = ts.date().isoformat() if ts else "unknown"
            bucket = per_day.setdefault(day, {"deny": 0, "ask": 0, "observe": 0, "allow": 0})
            if decision in ("block",):
                totals["deny"] += 1
                bucket["deny"] += 1
            elif decision == "ask":
                totals["ask"] += 1
                bucket["ask"] += 1
                asks[(sid, att.get("seq"))] = att
                rule_counts[_ask_rule(att)] = rule_counts.get(_ask_rule(att), 0) + 1
            elif decision == "observe":
                totals["observe"] += 1
                bucket["observe"] += 1
            elif decision in ("approve",):
                totals["allow"] += 1
                bucket["allow"] += 1
                ask_seq = (att.get("flow") or {}).get("ask_receipt_seq")
                if ask_seq is None:
                    ask_seq = (att.get("context") or {}).get("ask_receipt_seq")
                if ask_seq is not None and ts is not None:
                    approvals.append((sid, int(ask_seq), ts))
            elif decision == "allow_by_policy":
                totals["allow"] += 1
                bucket["allow"] += 1

    out.write("AgentBrake for Claude Code -- decision statistics")
    out.write(f" (last {days} day(s))\n" if days else " (all time)\n")
    out.write(f"  Sessions with receipts: {n_sessions}\n")
    out.write(f"  Totals: {totals['deny']} denied, {totals['ask']} asked, "
              f"{totals['observe']} observed (allowed, recorded), "
              f"{totals['allow']} allowed-after-ask/policy\n")

    delays: List[float] = []
    approved = 0
    for sid, ask_seq, approved_at in approvals:
        ask_att = asks.get((sid, ask_seq))
        if ask_att is None:
            continue
        approved += 1
        ask_ts = _parse_ts(ask_att.get("blocked_at"))
        if ask_ts is not None:
            delays.append((approved_at - ask_ts).total_seconds())

    if totals["ask"]:
        out.write(f"  Approval rate of asks: {approved}/{totals['ask']} "
                  f"({100 * approved / totals['ask']:.0f}%)\n")
        if delays:
            med = statistics.median(delays)
            fast = sum(1 for d in delays if d < 5)
            out.write(f"  Time from ask to the tool running after approval: "
                      f"median {med:.1f}s; {fast}/{len(delays)} "
                      f"({100 * fast / len(delays):.0f}%) under 5s\n")
            out.write("    NOTE: this is measured from the ask to the PostToolUse event, so it\n"
                      "    includes model and tool time, not only your decision time. A very\n"
                      "    short time still means the ask was cleared with little scrutiny.\n")
        else:
            out.write("  No approvals could be timed yet.\n")
        top = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        out.write("  Rules that asked most often:\n")
        for rule, count in top:
            out.write(f"    {count:>4}  {rule}\n")
    else:
        out.write("  No asks recorded in this window.\n")
    if per_day:
        out.write("  Per day (deny / ask / observe / allowed):\n")
        for day in sorted(per_day):
            b = per_day[day]
            out.write(f"    {day}  {b['deny']} / {b['ask']} / {b['observe']} / {b['allow']}\n")
    out.write("  (All figures come from local receipts only; nothing was sent anywhere.)\n")
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
