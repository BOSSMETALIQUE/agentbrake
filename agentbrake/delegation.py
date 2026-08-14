"""Signed delegation tokens: carry the user's original intent across agents.

The ASI03 problem (OWASP Agentic Top 10, Identity & Privilege Abuse): when
agent A hands a task to agent B, B typically inherits A's privileges with no
proof of what the *user* originally asked for. A low-privilege support agent
forwards a request to a high-privilege finance agent, and the finance agent
executes it without any way to check the original intent or its own mandate.

A **delegation token** closes that gap. When A delegates to B, A signs a
statement binding together:

* who delegates and to whom (``delegator`` -> ``delegatee``),
* the original user intent (text and/or its digest) — **invariant along the
  whole chain**, so a middle agent cannot quietly rewrite the mission,
* the delegated permissions (``allowed_tools`` — a subset of what A itself
  may do, and monotonically shrinking at every hop),
* a TTL (``expires_at`` — the *minimum* across the chain is what counts).

The delegatee runs under the token (``agentbrake.run(delegation=...)``): every
tool call is checked against the delegated scope *before* it executes, and any
call outside it trips the brake with ``InterruptReason.DELEGATION``. Tokens
are Ed25519-signed under their own domain (a token signature can never be
replayed as a receipt signature or vice versa) and verify with the public key
alone — the same third-party trust model as receipts.

Honest limitations:

* **Identity binding requires pinning.** A token names its ``delegator``; the
  signature proves only "signed by the holder of key X". Pass
  ``trusted_agents={agent_id: public_key_hex}`` to :func:`verify`/:func:`accept`
  to bind identities to keys you obtained out-of-band. Without pinning, the
  identity fields are claims.
* **The user's intent is attested by the first agent**, not signed by the user
  (users hold no key). The token freezes what the root delegator *declared*
  the intent to be; a compromised root agent can declare falsely. User-signed
  intents are future work.
* **Scope is tool names, not arguments.** "may refund at most $100" is not
  expressible yet.
* **TTLs compare against the local clock**, self-reported like every
  timestamp in this codebase.
* **Enforcement happens at the guarded dispatch.** A delegatee that reaches a
  tool without going through ``@guard()`` is outside our view — same boundary
  as every other detector.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import uuid4

from agentbrake import signing
from agentbrake.server import attest
from .types import InterruptReason, RunState, ToolCall

TOKEN_VERSION = "1"
CHAIN_FORMAT = "agentbrake-delegation-chain"


class DelegationError(Exception):
    """A delegation token could not be created or did not verify."""


def _now() -> datetime:
    """Module-level clock so tests can freeze time."""
    return datetime.now(timezone.utc)


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def intent_digest_for(intent: str) -> str:
    """``sha256:<hex>`` over the raw intent text (UTF-8)."""
    return "sha256:" + hashlib.sha256(intent.encode("utf-8")).hexdigest()


def _token_digest(token_json: str, signature: str) -> str:
    """Digest binding a signed token unit — what a child's parent field points at."""
    return "sha256:" + hashlib.sha256(
        (token_json + "." + signature).encode("utf-8")
    ).hexdigest()


def _sign_token(token_json: str, signer: signing.Signer) -> str:
    return signer.sign(signing.DOMAIN_DELEGATION_V1 + token_json.encode("utf-8"))


def _verify_token_signature(token_json: str, signature: str, public_key_hex: str) -> bool:
    message = signing.DOMAIN_DELEGATION_V1 + token_json.encode("utf-8")
    return signing.verify_ed25519(public_key_hex, message, signature)


class DelegationToken:
    """A delegation chain: one or more signed links, root grant first.

    Only the signed bytes (``token_json``) and signatures are authoritative;
    parsed bodies are derived views. Serialize with :meth:`to_dict` (JSON-safe)
    and reload with :meth:`from_dict`.
    """

    def __init__(self, links: List[Dict[str, str]]):
        if not links:
            raise DelegationError("a delegation chain needs at least one link")
        self.links = [
            {"token_json": link["token_json"], "signature": link["signature"]}
            for link in links
        ]
        try:
            self.bodies: List[Dict[str, Any]] = [
                json.loads(link["token_json"]) for link in self.links
            ]
        except json.JSONDecodeError as e:
            raise DelegationError(f"unparseable token body: {e}") from e
        self.digests = [
            _token_digest(link["token_json"], link["signature"]) for link in self.links
        ]

    # ----- derived views of the *leaf* grant (what the delegatee runs under) --

    @property
    def leaf(self) -> Dict[str, Any]:
        return self.bodies[-1]

    @property
    def delegator(self) -> str:
        """The root delegator — where the chain of authority starts."""
        return self.bodies[0].get("delegator")

    @property
    def delegatee(self) -> str:
        return self.leaf.get("delegatee")

    @property
    def allowed_tools(self) -> List[str]:
        return list(self.leaf.get("allowed_tools") or [])

    @property
    def intent(self) -> Optional[str]:
        return self.leaf.get("intent")

    @property
    def intent_digest(self) -> Optional[str]:
        return self.leaf.get("intent_digest")

    @property
    def digest(self) -> str:
        """Digest of the leaf link — used as parent binding and in receipts."""
        return self.digests[-1]

    def effective_expires_at(self) -> Optional[datetime]:
        """The chain expires when its *earliest* link expires."""
        stamps = [_parse_ts(b.get("expires_at")) for b in self.bodies]
        stamps = [s for s in stamps if s is not None]
        return min(stamps) if stamps else None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        expires = self.effective_expires_at()
        if expires is None:
            return True  # a token without a readable expiry is not honored
        return (now or _now()) >= expires

    # ----- (de)serialization ---------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {"format": CHAIN_FORMAT, "version": TOKEN_VERSION, "links": list(self.links)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationToken":
        if data.get("format") != CHAIN_FORMAT:
            raise DelegationError(f"not a delegation chain: format={data.get('format')!r}")
        return cls(data.get("links") or [])


# ----- granting --------------------------------------------------------------

def grant(
    *,
    delegator: str,
    delegatee: str,
    tools: Iterable[str],
    ttl_seconds: float,
    intent: Optional[str] = None,
    intent_digest: Optional[str] = None,
    parent: Optional[DelegationToken] = None,
    signer: Optional[signing.Signer] = None,
    issued_at: Optional[datetime] = None,
    ledger: Optional[Any] = None,
) -> DelegationToken:
    """Create and sign one delegation link; returns the full chain.

    Root grant: ``intent`` (or ``intent_digest``) is required — it is the
    user's original ask, frozen for the life of the chain. Sub-delegation:
    pass ``parent``; the intent is inherited and immutable, and ``tools`` must
    be a subset of the parent's. ``signer`` defaults to the process signer
    and must be Ed25519 — delegation has no legacy-HMAC mode, because a token
    that any verifier could forge would not carry authority anywhere.

    The grant is receipted: a ``delegation_grant`` receipt is minted into the
    active run's ledger (or an explicit ``ledger``), embedding the full signed
    token. A grant issued outside any run and without a ledger produces no
    receipt — if the audit trail matters there, pass one.
    """
    active_signer = signer if signer is not None else attest.SIGNER
    if active_signer.alg != signing.ALG_ED25519:
        raise DelegationError(
            "delegation requires an Ed25519 signer; the legacy HMAC signing key "
            "cannot mint tokens a third party could trust"
        )
    if not delegator or not delegatee:
        raise DelegationError("delegator and delegatee must be non-empty")
    tool_list = sorted(set(tools))
    if not tool_list:
        raise DelegationError("a delegation must scope at least one tool")
    if ttl_seconds <= 0:
        raise DelegationError("ttl_seconds must be positive")

    if parent is not None:
        if delegator != parent.delegatee:
            raise DelegationError(
                f"delegator {delegator!r} does not match the parent's delegatee "
                f"{parent.delegatee!r} — only the current holder may sub-delegate"
            )
        widened = set(tool_list) - set(parent.allowed_tools)
        if widened:
            raise DelegationError(
                f"sub-delegation may only narrow scope; not in parent scope: "
                f"{sorted(widened)}"
            )
        inherited_digest = parent.intent_digest
        if intent is not None and intent_digest_for(intent) != inherited_digest:
            raise DelegationError("intent text does not match the parent's intent digest")
        effective_intent = intent if intent is not None else parent.intent
        effective_digest = inherited_digest
    else:
        if intent is None and intent_digest is None:
            raise DelegationError("a root grant must carry the user intent (or its digest)")
        effective_intent = intent
        effective_digest = intent_digest or intent_digest_for(intent)
        if intent is not None and intent_digest is not None:
            if intent_digest_for(intent) != intent_digest:
                raise DelegationError("intent text and intent_digest disagree")

    issued = issued_at or _now()
    body = {
        "version": TOKEN_VERSION,
        "alg": active_signer.alg,
        "key_id": active_signer.key_id,
        "token_id": str(uuid4()),
        "delegator": delegator,
        "delegatee": delegatee,
        "intent": effective_intent,
        "intent_digest": effective_digest,
        "allowed_tools": tool_list,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "parent_token_digest": parent.digest if parent is not None else None,
    }
    token_json = attest.canonical_json(body, strict=True)
    signature = _sign_token(token_json, active_signer)
    link = {"token_json": token_json, "signature": signature}
    links = (parent.links + [link]) if parent is not None else [link]
    token = DelegationToken(links)
    record_event("delegation_grant", "grant", token, ledger=ledger)
    return token


# ----- receipts for delegation decisions ---------------------------------------

def token_receipt_payload(token: DelegationToken) -> Dict[str, Any]:
    """The receipt payload for a token: full signed links plus derived facts.

    Embedding the links (not just a digest) is what lets an auditor re-verify
    the delegation itself from the receipt chain alone — see the
    ``delegation_tokens`` deep check in :mod:`agentbrake.export`.
    """
    expires = token.effective_expires_at()
    return {
        "links": [dict(link) for link in token.links],
        "token_digest": token.digest,
        "delegator": token.delegator,
        "delegatee": token.delegatee,
        "intent_digest": token.intent_digest,
        "allowed_tools": token.allowed_tools,
        "expires_at": expires.isoformat() if expires else None,
    }


def record_event(
    kind: str,
    decision: str,
    token: DelegationToken,
    *,
    ledger: Optional[Any] = None,
    run_id: Optional[str] = None,
    tool: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Mint a signed, chained receipt for one delegation decision.

    With no explicit ``ledger``, the active run's ledger is used; outside any
    run the event goes unreceipted and None is returned (documented behavior —
    receipts live in a run's chain).
    """
    from . import receipts  # local import: receipts is independent of this module

    if ledger is None:
        from agentbrake import current_run  # deferred: the package imports us

        active = current_run()
        if active is None:
            return None
        ledger = active.flow_ledger
        run_id = active.state.run_id

    payload = token_receipt_payload(token)
    if extra:
        payload.update(extra)
    return receipts.mint_delegation_receipt(
        ledger,
        kind=kind,
        decision=decision,
        run_id=run_id,
        delegation=payload,
        tool=tool,
        agent_id=token.delegatee,
    )


# ----- verification -----------------------------------------------------------

def verify(
    token: DelegationToken,
    *,
    trusted_agents: Optional[Dict[str, str]] = None,
    public_keys: Optional[Dict[str, str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Verify a delegation chain. Returns a structured report, never raises.

    Trust resolution, strictest first:

    * ``trusted_agents`` ({agent_id: public_key_hex}) — each link must be
      signed under the key pinned for its *delegator identity*. This is the
      mode that actually answers ASI03; use it whenever keys can be exchanged
      out-of-band.
    * ``public_keys`` ({key_id: public_key_hex}) — key-level verification
      without identity binding (the receipts model).
    * neither — fall back to the process signer, which only covers
      same-process tokens (self-check).
    """
    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"name": name, "ok": ok, "detail": detail})
        return ok

    bodies, links = token.bodies, token.links

    structure_ok = all(
        isinstance(b.get("delegator"), str)
        and isinstance(b.get("delegatee"), str)
        and isinstance(b.get("allowed_tools"), list)
        and b.get("version") == TOKEN_VERSION
        for b in bodies
    )
    check("structure", structure_ok, f"{len(links)} link(s), version {TOKEN_VERSION}")

    if trusted_agents is not None:
        mode = "pinned_identities"
    elif public_keys is not None:
        mode = "key_ids"
    else:
        mode = "process_signer"

    sig_ok, sig_detail = True, f"all {len(links)} signature(s) valid [{mode}]"
    for i, (body, link) in enumerate(zip(bodies, links)):
        if body.get("alg") != signing.ALG_ED25519:
            sig_ok, sig_detail = False, f"link {i}: unsupported alg {body.get('alg')!r}"
            break
        if trusted_agents is not None:
            pub = trusted_agents.get(body.get("delegator"))
            if pub is None:
                sig_ok = False
                sig_detail = (
                    f"link {i}: delegator {body.get('delegator')!r} has no pinned key"
                )
                break
        elif public_keys is not None:
            pub = public_keys.get(body.get("key_id"))
            if pub is None:
                sig_ok, sig_detail = False, f"link {i}: unknown key_id {body.get('key_id')}"
                break
        else:
            signer = attest.SIGNER
            pub = (
                signer.public_key_hex()
                if signer.alg == signing.ALG_ED25519
                and signer.key_id == body.get("key_id")
                else None
            )
            if pub is None:
                sig_ok = False
                sig_detail = (
                    f"link {i}: key_id {body.get('key_id')} is not this process's "
                    "signer — pass trusted_agents or public_keys"
                )
                break
        if not _verify_token_signature(link["token_json"], link["signature"], pub):
            sig_ok, sig_detail = False, f"link {i}: signature invalid — token altered or forged"
            break
    check("signatures", sig_ok, sig_detail)

    identity_ok, identity_detail = True, "delegatee of each link is the next delegator"
    for i in range(1, len(bodies)):
        if bodies[i].get("delegator") != bodies[i - 1].get("delegatee"):
            identity_ok = False
            identity_detail = (
                f"link {i}: delegator {bodies[i].get('delegator')!r} is not the "
                f"previous delegatee {bodies[i - 1].get('delegatee')!r}"
            )
            break
    check("identity_chain", identity_ok, identity_detail)

    binding_ok, binding_detail = True, "each link commits to its parent's digest"
    if bodies[0].get("parent_token_digest") is not None:
        binding_ok, binding_detail = False, "root link claims a parent — truncated chain?"
    else:
        for i in range(1, len(bodies)):
            if bodies[i].get("parent_token_digest") != token.digests[i - 1]:
                binding_ok = False
                binding_detail = f"link {i}: parent digest mismatch — chain spliced?"
                break
    check("parent_binding", binding_ok, binding_detail)

    scope_ok, scope_detail = True, "scope narrows (or holds) at every hop"
    for i in range(1, len(bodies)):
        widened = set(bodies[i].get("allowed_tools") or []) - set(
            bodies[i - 1].get("allowed_tools") or []
        )
        if widened:
            scope_ok = False
            scope_detail = f"link {i} WIDENS scope with {sorted(widened)} — privilege escalation"
            break
    check("scope_monotonic", scope_ok, scope_detail)

    digests = {b.get("intent_digest") for b in bodies}
    intent_ok = len(digests) == 1 and None not in digests
    intent_detail = "intent digest identical across the chain"
    if not intent_ok:
        intent_detail = "intent digest changed mid-chain — the mission was rewritten"
    else:
        for i, body in enumerate(bodies):
            text = body.get("intent")
            if text is not None and intent_digest_for(text) != body.get("intent_digest"):
                intent_ok = False
                intent_detail = f"link {i}: intent text does not match its own digest"
                break
    check("intent_invariant", intent_ok, intent_detail)

    expires = token.effective_expires_at()
    expired = token.is_expired(now)
    check(
        "not_expired",
        not expired,
        f"effective expiry {expires.isoformat() if expires else '(unreadable)'}",
    )

    return {
        "ok": all(c["ok"] for c in checks),
        "mode": mode,
        "chain_length": len(links),
        "delegator": token.delegator,
        "delegatee": token.delegatee,
        "allowed_tools": token.allowed_tools,
        "intent_digest": token.intent_digest,
        "expires_at": expires.isoformat() if expires else None,
        "token_digest": token.digest,
        "checks": checks,
    }


def accept(
    token: DelegationToken,
    *,
    trusted_agents: Optional[Dict[str, str]] = None,
    public_keys: Optional[Dict[str, str]] = None,
    now: Optional[datetime] = None,
) -> "AcceptedDelegation":
    """Verify a token and, on success, wrap it for use by a Run.

    Raises :class:`DelegationError` if any check fails. This is the
    delegatee's acceptance decision: call it with ``trusted_agents`` when the
    token comes from another process, then pass the result to
    ``agentbrake.run(delegation=...)``.
    """
    report = verify(
        token, trusted_agents=trusted_agents, public_keys=public_keys, now=now
    )
    if not report["ok"]:
        failed = [c for c in report["checks"] if not c["ok"]]
        raise DelegationError(
            "delegation rejected: " + "; ".join(c["detail"] for c in failed)
        )
    return AcceptedDelegation(token, report)


class AcceptedDelegation:
    """A token that passed :func:`accept`, ready to hand to a Run."""

    def __init__(self, token: DelegationToken, report: Dict[str, Any]):
        self.token = token
        self.report = report
        self.accepted_at = _now().isoformat()


# ----- enforcement (wired into the guard loop) ---------------------------------

class DelegationDetector:
    """Blocks tool calls outside the delegated scope, or after expiry.

    Runs before every other detector: identity and mandate come first. The
    cryptographic verification happened once at acceptance; per-call checks
    are pure scope + clock, so the hot path stays cheap.
    """

    def __init__(self, accepted: AcceptedDelegation):
        self.accepted = accepted
        self.token = accepted.token
        self._allowed = set(self.token.allowed_tools)

    def check(self, run_state: RunState, new_call: ToolCall) -> Optional[InterruptReason]:
        if self.token.is_expired():
            return InterruptReason.DELEGATION
        if new_call.name not in self._allowed:
            return InterruptReason.DELEGATION
        return None

    def explain(self, new_call: ToolCall) -> Dict[str, Any]:
        """Receipt- and human-readable detail of why a call was refused."""
        expired = self.token.is_expired()
        expires = self.token.effective_expires_at()
        return {
            "violation": "expired" if expired else "out_of_scope",
            "tool": new_call.name,
            "allowed_tools": sorted(self._allowed),
            "delegator": self.token.delegator,
            "delegatee": self.token.delegatee,
            "intent_digest": self.token.intent_digest,
            "token_digest": self.token.digest,
            "expires_at": expires.isoformat() if expires else None,
        }
