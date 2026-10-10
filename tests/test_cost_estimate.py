"""The flat per-call charge is labeled an estimate everywhere it surfaces."""

from __future__ import annotations

from pathlib import Path

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason, signing
from agentbrake.server import attest
from agentbrake.types import RunState, ToolCall

TEST_SIGNER = signing.Ed25519Signer.from_seed(b"\x0f" * 32)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(attest, "SIGNER", TEST_SIGNER)
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


@agentbrake.guard()
def dispatch(name: str, args: dict) -> str:
    return "ok"


def test_guarded_calls_are_marked_as_estimated():
    with agentbrake.run(allowed_tools=["t"], budget_usd=1.0) as r:
        assert r.state.cost_is_estimate is False  # nothing charged yet
        dispatch("t", {"i": 1})
        dispatch("t", {"i": 2})
    assert all(c.cost_estimated for c in r.state.calls)
    assert r.state.cost_is_estimate is True
    # The figure itself and the budget semantics are unchanged.
    assert r.state.total_cost_usd == pytest.approx(2 * agentbrake.ESTIMATED_COST_PER_TOOL_CALL_USD)


def test_priced_calls_alone_are_not_an_estimate():
    state = RunState()
    state.append(ToolCall(name="llm:cometapi:gpt-4o", cost_usd=0.0123, outcome="ok"))
    assert state.cost_is_estimate is False
    state.append(ToolCall(name="t", cost_usd=0.01, cost_estimated=True))
    assert state.cost_is_estimate is True


def test_tool_call_defaults_stay_backward_compatible():
    call = ToolCall(name="t", cost_usd=0.5)
    assert call.cost_estimated is False
    assert call.cost_usd == pytest.approx(0.5)


def test_budget_still_trips_at_the_same_call():
    with agentbrake.run(allowed_tools=["t"], budget_usd=0.025):
        dispatch("t", {"i": 1})
        dispatch("t", {"i": 2})
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {"i": 3})  # projected 0.03 > 0.025
    e = ei.value
    assert e.reason is InterruptReason.BUDGET
    assert e.context["cost_is_estimate"] is True
    # The signed receipt says so too, next to the figure it qualifies.
    receipt_ctx = e.receipt["attestation"]["context"]
    assert receipt_ctx["total_cost_usd"] == pytest.approx(0.02)
    assert receipt_ctx["total_cost_is_estimate"] is True


def test_first_call_budget_block_is_flagged_as_estimate():
    # No prior calls, but the pending call's placeholder is what tripped it.
    with agentbrake.run(allowed_tools=["t"], budget_usd=0.005):
        with pytest.raises(AgentBrakeInterrupt) as ei:
            dispatch("t", {})
    assert ei.value.context["cost_is_estimate"] is True


def test_cometapi_record_reports_estimate_flag():
    from agentbrake.providers import cometapi

    with agentbrake.run(allowed_tools=["t"], budget_usd=0.015):
        dispatch("t", {})  # flat placeholder in the run
        call = cometapi.CometAPICall(
            model="gpt-4o", prompt_tokens=1, completion_tokens=1, cost_usd=0.01, response=None
        )
        with pytest.raises(AgentBrakeInterrupt) as ei:
            cometapi.record(call)
    assert ei.value.context["cost_is_estimate"] is True


# --- validation page ------------------------------------------------------------

@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from fastapi.testclient import TestClient

    from agentbrake.server import main as server_main
    from agentbrake.server import security, store

    db_path = tmp_path / "test.db"
    monkeypatch.setattr(store, "DEFAULT_DB_PATH", db_path)
    monkeypatch.setattr(security, "SDK_SECRET", "sdk-test")
    monkeypatch.setattr(security, "APPROVER_SECRET", "approver-test")
    store.init_db(db_path)
    return TestClient(server_main.app)


def _page(client, context: dict) -> str:
    resp = client.post(
        "/interrupts",
        json={"run_id": "r", "reason": "BUDGET", "context": context},
        headers={"X-SDK-Secret": "sdk-test"},
    )
    assert resp.status_code == 200
    return client.get(f"/interrupts/{resp.json()['interrupt_id']}").text


def test_validation_page_labels_estimate(client):
    html = _page(client, {"tool": "t", "total_cost_usd": 0.05, "cost_is_estimate": True})
    assert "Estimated cost" in html
    assert "not a measured price" in html
    assert "Total cost" not in html


def test_validation_page_keeps_label_for_older_sdks(client):
    html = _page(client, {"tool": "t", "total_cost_usd": 0.05})
    assert "Total cost" in html
    assert "Estimated cost" not in html
