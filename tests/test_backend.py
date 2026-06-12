"""Backend route tests using FastAPI TestClient + a temp SQLite file."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentbrake.server import main as server_main
from agentbrake.server import store


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(store, "DEFAULT_DB_PATH", db_path)
    store.init_db(db_path)
    return TestClient(server_main.app)


def _sample_payload() -> dict:
    return {
        "run_id": "run-123",
        "reason": "LOOP",
        "context": {
            "tool": "search",
            "total_cost_usd": 0.05,
            "run_state": {
                "run_id": "run-123",
                "calls": [{"name": "search", "args": {"q": "x"}}],
            },
        },
    }


def test_create_interrupt_persists(client: TestClient) -> None:
    resp = client.post("/interrupts", json=_sample_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert "interrupt_id" in body
    assert body["validation_url"].endswith(f"/interrupts/{body['interrupt_id']}")

    status_resp = client.get(f"/interrupts/{body['interrupt_id']}/status")
    assert status_resp.status_code == 200
    assert status_resp.json() == {"status": "pending"}


def test_get_interrupt_returns_html(client: TestClient) -> None:
    created = client.post("/interrupts", json=_sample_payload()).json()
    resp = client.get(f"/interrupts/{created['interrupt_id']}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    html = resp.text
    assert "AgentBrake interrupt" in html
    assert "LOOP" in html
    assert "Approve" in html and "Kill" in html


def test_decide_changes_status(client: TestClient) -> None:
    created = client.post("/interrupts", json=_sample_payload()).json()
    iid = created["interrupt_id"]

    resp = client.post(f"/interrupts/{iid}/decide", json={"decision": "approve"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "approved"}

    status_resp = client.get(f"/interrupts/{iid}/status")
    assert status_resp.json() == {"status": "approved"}


def test_full_workflow_pending_to_killed(client: TestClient) -> None:
    created = client.post("/interrupts", json=_sample_payload()).json()
    iid = created["interrupt_id"]

    assert client.get(f"/interrupts/{iid}/status").json()["status"] == "pending"

    client.post(f"/interrupts/{iid}/decide", json={"decision": "kill"})
    assert client.get(f"/interrupts/{iid}/status").json()["status"] == "killed"

    # The HTML view should now show the "killed" terminal state, not the form.
    page = client.get(f"/interrupts/{iid}").text
    assert "Killed" in page
    assert "Approve & Continue" not in page


def test_decide_invalid_value(client: TestClient) -> None:
    created = client.post("/interrupts", json=_sample_payload()).json()
    resp = client.post(
        f"/interrupts/{created['interrupt_id']}/decide",
        json={"decision": "maybe"},
    )
    assert resp.status_code == 400


def test_get_missing_interrupt_returns_404(client: TestClient) -> None:
    assert client.get("/interrupts/does-not-exist/status").status_code == 404
    assert client.get("/interrupts/does-not-exist").status_code == 404


# --- Default DB path resolution -------------------------------------------

def test_default_db_path_is_cwd_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENTBRAKE_DB", raising=False)
    monkeypatch.chdir(tmp_path)
    assert store._default_db_path() == tmp_path / "agentbrake.db"


def test_agentbrake_db_env_var_overrides_db_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "custom" / "brake.db"
    monkeypatch.setenv("AGENTBRAKE_DB", str(target))
    assert store._default_db_path() == target
