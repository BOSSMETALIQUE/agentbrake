"""Tests for the SDK HTTP client's credential surface.

The security guarantee is structural: the client can create interrupts and poll
status, but it holds no approver secret and exposes no way to approve. These
tests pin that surface so a future change can't quietly hand the agent the
ability to wave itself through.
"""

from __future__ import annotations

import pytest

from agentbrake.client import AgentBrakeClient


def test_client_sends_sdk_secret_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTBRAKE_SDK_SECRET", "sdk-only")
    monkeypatch.delenv("AGENTBRAKE_APPROVER_SECRET", raising=False)
    c = AgentBrakeClient("http://localhost:8000")
    try:
        assert c.sdk_secret == "sdk-only"
        assert c._http.headers.get("x-sdk-secret") == "sdk-only"
    finally:
        c.close()


def test_client_never_carries_an_approver_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even if an approver secret is present in the environment, the client must
    # not pick it up or send it anywhere.
    monkeypatch.setenv("AGENTBRAKE_SDK_SECRET", "sdk-only")
    monkeypatch.setenv("AGENTBRAKE_APPROVER_SECRET", "approver-secret")
    c = AgentBrakeClient("http://localhost:8000")
    try:
        assert "x-approver-secret" not in c._http.headers
        assert "approver-secret" not in str(dict(c._http.headers)).lower()
    finally:
        c.close()


def test_client_exposes_no_approve_or_decide_method() -> None:
    assert not hasattr(AgentBrakeClient, "approve")
    assert not hasattr(AgentBrakeClient, "decide")
    # Only create + poll + close are part of the surface.
    public = {n for n in vars(AgentBrakeClient) if not n.startswith("_")}
    assert public == {"submit_interrupt", "get_status", "wait_for_decision", "close"}
