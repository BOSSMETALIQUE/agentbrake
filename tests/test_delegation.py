"""Delegation tokens: granting, chain verification, and guard enforcement.

The forged-chain tests build token links by hand (bypassing grant(), which
refuses to create them) — a verifier must reject anything grant() would not
have produced, because an attacker is not obliged to use our API.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, DelegationError, InterruptReason, delegation, signing
from agentbrake.server import attest

SIGNER_A = signing.Ed25519Signer.from_seed(b"\x08" * 32)  # support-agent
SIGNER_B = signing.Ed25519Signer.from_seed(b"\x09" * 32)  # finance-agent
SIGNER_C = signing.Ed25519Signer.from_seed(b"\x0a" * 32)  # payment-bot

TRUSTED = {
    "support-agent": SIGNER_A.public_key_hex(),
    "finance-agent": SIGNER_B.public_key_hex(),
}

INTENT = "Refund order #4521 for jane@corp.com"


@pytest.fixture(autouse=True)
def _fixed_signer(monkeypatch: pytest.MonkeyPatch):
    """The process signs as agent A by default; runs accept its tokens."""
    monkeypatch.setattr(attest, "SIGNER", SIGNER_A)


@pytest.fixture(autouse=True)
def _isolate_default_run():
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


def _grant_root(**overrides) -> delegation.DelegationToken:
    kwargs = dict(
        delegator="support-agent",
        delegatee="finance-agent",
        intent=INTENT,
        tools=["lookup_order", "issue_refund"],
        ttl_seconds=300,
    )
    kwargs.update(overrides)
    return delegation.grant(**kwargs)


def _forge_child(parent: delegation.DelegationToken, body_overrides: dict,
                 signer=SIGNER_B) -> delegation.DelegationToken:
    """Hand-build a (validly signed) child link that grant() would refuse."""
    body = {
        "version": "1",
        "alg": "ed25519",
        "key_id": signer.key_id,
        "token_id": "forged",
        "delegator": parent.delegatee,
        "delegatee": "payment-bot",
        "intent": None,
        "intent_digest": parent.intent_digest,
        "allowed_tools": ["issue_refund"],
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(),
        "parent_token_digest": parent.digest,
    }
    body.update(body_overrides)
    token_json = attest.canonical_json(body, strict=True)
    signature = signer.sign(signing.DOMAIN_DELEGATION_V1 + token_json.encode("utf-8"))
    return delegation.DelegationToken(
        parent.links + [{"token_json": token_json, "signature": signature}]
    )


def _failed(report: dict, name: str) -> bool:
    return not next(c["ok"] for c in report["checks"] if c["name"] == name)


# --- granting -----------------------------------------------------------------

def test_grant_produces_verifiable_token():
    token = _grant_root()
    assert token.delegator == "support-agent"
    assert token.delegatee == "finance-agent"
    assert token.allowed_tools == ["issue_refund", "lookup_order"]
    assert token.intent_digest == delegation.intent_digest_for(INTENT)
    report = delegation.verify(token)  # process-signer fallback
    assert report["ok"], report["checks"]
    assert report["mode"] == "process_signer"


def test_token_serialization_roundtrip():
    token = _grant_root()
    reloaded = delegation.DelegationToken.from_dict(token.to_dict())
    assert reloaded.digest == token.digest
    assert delegation.verify(reloaded)["ok"] is True


def test_grant_input_validation():
    with pytest.raises(DelegationError):
        _grant_root(intent=None)  # root without intent
    with pytest.raises(DelegationError):
        _grant_root(tools=[])
    with pytest.raises(DelegationError):
        _grant_root(ttl_seconds=0)
    with pytest.raises(DelegationError):
        _grant_root(delegatee="")


def test_grant_refuses_legacy_hmac_signer():
    with pytest.raises(DelegationError):
        _grant_root(signer=signing.HmacSigner(b"legacy"))


def test_subdelegation_must_narrow_scope():
    root = _grant_root()
    with pytest.raises(DelegationError):
        delegation.grant(
            delegator="finance-agent",
            delegatee="payment-bot",
            tools=["issue_refund", "delete_db"],  # widens
            ttl_seconds=60,
            parent=root,
            signer=SIGNER_B,
        )


def test_subdelegation_only_by_current_holder():
    root = _grant_root()
    with pytest.raises(DelegationError):
        delegation.grant(
            delegator="someone-else",  # not the parent's delegatee
            delegatee="payment-bot",
            tools=["issue_refund"],
            ttl_seconds=60,
            parent=root,
            signer=SIGNER_B,
        )


# --- verification: identity pinning & tampering --------------------------------

def test_pinned_identities_verify_and_bind():
    token = _grant_root(signer=SIGNER_A)
    assert delegation.verify(token, trusted_agents=TRUSTED)["ok"] is True

    # Same token, but the verifier pins a DIFFERENT key for support-agent:
    # the identity claim no longer holds.
    wrong = dict(TRUSTED, **{"support-agent": SIGNER_C.public_key_hex()})
    report = delegation.verify(token, trusted_agents=wrong)
    assert report["ok"] is False and _failed(report, "signatures")

    # Unpinned delegator identity fails closed.
    report = delegation.verify(token, trusted_agents={})
    assert report["ok"] is False and _failed(report, "signatures")


def test_tampered_token_body_fails():
    token = _grant_root()
    link = dict(token.links[0])
    link["token_json"] = link["token_json"].replace(
        '"delegatee":"finance-agent"', '"delegatee":"evil-agent"'
    )
    forged = delegation.DelegationToken([link])
    report = delegation.verify(forged)
    assert report["ok"] is False and _failed(report, "signatures")


def test_expired_token_fails_verification():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = _grant_root(issued_at=past, ttl_seconds=5)
    report = delegation.verify(token)
    assert report["ok"] is False and _failed(report, "not_expired")
    with pytest.raises(DelegationError):
        delegation.accept(token)


# --- chains A -> B -> C ---------------------------------------------------------

def test_valid_chain_verifies_with_leaf_scope():
    root = _grant_root(signer=SIGNER_A)
    sub = delegation.grant(
        delegator="finance-agent",
        delegatee="payment-bot",
        tools=["issue_refund"],
        ttl_seconds=60,
        parent=root,
        signer=SIGNER_B,
    )
    report = delegation.verify(sub, trusted_agents=TRUSTED)
    assert report["ok"], report["checks"]
    assert report["chain_length"] == 2
    assert report["delegator"] == "support-agent"      # authority root
    assert report["delegatee"] == "payment-bot"        # current holder
    assert report["allowed_tools"] == ["issue_refund"]  # leaf scope
    assert sub.intent_digest == root.intent_digest      # mission unchanged


def test_forged_chain_widened_scope_fails():
    root = _grant_root()
    forged = _forge_child(root, {"allowed_tools": ["issue_refund", "delete_db"]})
    report = delegation.verify(forged, trusted_agents=TRUSTED)
    assert report["ok"] is False and _failed(report, "scope_monotonic")


def test_forged_chain_identity_break_fails():
    root = _grant_root()
    forged = _forge_child(root, {"delegator": "impostor-agent"})
    report = delegation.verify(forged, trusted_agents=dict(
        TRUSTED, **{"impostor-agent": SIGNER_B.public_key_hex()}
    ))
    assert report["ok"] is False and _failed(report, "identity_chain")


def test_forged_chain_rewritten_intent_fails():
    root = _grant_root()
    forged = _forge_child(
        root, {"intent_digest": delegation.intent_digest_for("Wire everything to evil corp")}
    )
    report = delegation.verify(forged, trusted_agents=TRUSTED)
    assert report["ok"] is False and _failed(report, "intent_invariant")


def test_forged_chain_broken_parent_binding_fails():
    root = _grant_root()
    forged = _forge_child(root, {"parent_token_digest": "sha256:" + "ab" * 32})
    report = delegation.verify(forged, trusted_agents=TRUSTED)
    assert report["ok"] is False and _failed(report, "parent_binding")


def test_chain_effective_expiry_is_the_minimum():
    root = _grant_root(ttl_seconds=10)
    sub = delegation.grant(
        delegator="finance-agent",
        delegatee="payment-bot",
        tools=["issue_refund"],
        ttl_seconds=99999,  # the child cannot outlive its parent
        parent=root,
        signer=SIGNER_B,
    )
    root_expiry = root.effective_expires_at()
    assert sub.effective_expires_at() == root_expiry


# --- guard enforcement -----------------------------------------------------------

@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return f"{name}-ok"


def test_run_within_delegated_scope_passes():
    token = _grant_root()
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund"],
        budget_usd=10.0,
        delegation=token,
    ) as r:
        assert dispatch("lookup_order", {"id": 4521}) == "lookup_order-ok"
        assert dispatch("issue_refund", {"id": 4521}) == "issue_refund-ok"
    assert r.state.status == "completed"


def test_run_out_of_scope_trips_delegation():
    token = _grant_root()
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund", "send_email"],
        budget_usd=10.0,
        delegation=token,
    ):
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("send_email", {"to": "x@y.z"})  # allow-listed, NOT delegated
    assert ei.value.reason is InterruptReason.DELEGATION
    detail = ei.value.context["delegation"]
    assert detail["violation"] == "out_of_scope"
    assert detail["tool"] == "send_email"
    assert detail["delegator"] == "support-agent"


def test_allowlist_still_applies_inside_delegated_scope():
    """Effective permissions are the INTERSECTION of allowlist and token."""
    token = _grant_root()  # delegates lookup_order + issue_refund
    with agentbrake.run(
        allowed_tools=["lookup_order"],  # run itself does not allow issue_refund
        budget_usd=10.0,
        delegation=token,
    ):
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("issue_refund", {})
    assert ei.value.reason is InterruptReason.ESCALATION


def test_token_expiring_mid_run_blocks(monkeypatch: pytest.MonkeyPatch):
    token = _grant_root(ttl_seconds=3600)
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund"],
        budget_usd=10.0,
        delegation=token,
    ):
        assert dispatch("lookup_order", {}) == "lookup_order-ok"
        # The clock jumps past the TTL while the run is still going.
        monkeypatch.setattr(
            delegation, "_now",
            lambda: datetime.now(timezone.utc) + timedelta(hours=2),
        )
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("issue_refund", {})
    assert ei.value.reason is InterruptReason.DELEGATION
    assert ei.value.context["delegation"]["violation"] == "expired"


def test_run_rejects_invalid_token_at_creation():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = _grant_root(issued_at=past, ttl_seconds=5)
    with pytest.raises(DelegationError):
        agentbrake.run(allowed_tools=["lookup_order"], delegation=expired)


def test_run_accepts_pre_verified_delegation():
    token = _grant_root(signer=SIGNER_A)
    accepted = delegation.accept(token, trusted_agents=TRUSTED)
    with agentbrake.run(
        allowed_tools=["lookup_order", "issue_refund"],
        budget_usd=10.0,
        delegation=accepted,
    ):
        assert dispatch("lookup_order", {}) == "lookup_order-ok"


def test_run_rejects_garbage_delegation_argument():
    with pytest.raises(TypeError):
        agentbrake.run(allowed_tools=["x"], delegation="not-a-token")


def test_runs_without_delegation_are_unchanged():
    with agentbrake.run(allowed_tools=["search"], budget_usd=10.0) as r:
        assert dispatch("search", {"q": "x"}) == "search-ok"
    assert r.delegation_detector is None