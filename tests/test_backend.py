"""Backend route tests using FastAPI TestClient + a temp SQLite file."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentbrake.server import main as server_main
from agentbrake.server import security, store

SDK_SECRET = "test-sdk-secret"
APPROVER_SECRET = "test-approver-secret"
SDK_HEADERS = {"X-SDK-Secret": SDK_SECRET}
APPROVER_HEADERS = {"X-Approver-Secret": APPROVER_SECRET}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(store, "DEFAULT_DB_PATH", db_path)
    monkeypatch.setattr(security, "SDK_SECRET", SDK_SECRET)
    monkeypatch.setattr(security, "APPROVER_SECRET", APPROVER_SECRET)
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


def _create(client: TestClient) -> str:
    """Create an interrupt with valid SDK auth and return its id."""
    resp = client.post("/interrupts", json=_sample_payload(), headers=SDK_HEADERS)
    assert resp.status_code == 200
    return resp.json()["interrupt_id"]


def test_create_interrupt_persists(client: TestClient) -> None:
    resp = client.post("/interrupts", json=_sample_payload(), headers=SDK_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert "interrupt_id" in body
    assert body["validation_url"].endswith(f"/interrupts/{body['interrupt_id']}")

    status_resp = client.get(
        f"/interrupts/{body['interrupt_id']}/status", headers=SDK_HEADERS
    )
    assert status_resp.status_code == 200
    assert status_resp.json() == {"status": "pending"}


def test_get_interrupt_returns_html(client: TestClient) -> None:
    iid = _create(client)
    resp = client.get(f"/interrupts/{iid}")  # HTML view stays open (no secret)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    html = resp.text
    assert "AgentBrake interrupt" in html
    assert "LOOP" in html
    assert "Approve" in html and "Kill" in html


def test_decide_changes_status(client: TestClient) -> None:
    iid = _create(client)

    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve"},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "approved"}

    status_resp = client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS)
    assert status_resp.json() == {"status": "approved"}


def test_full_workflow_pending_to_killed(client: TestClient) -> None:
    iid = _create(client)

    assert (
        client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).json()["status"]
        == "pending"
    )

    client.post(
        f"/interrupts/{iid}/decide", json={"decision": "kill"}, headers=APPROVER_HEADERS
    )
    assert (
        client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).json()["status"]
        == "killed"
    )

    # The HTML view should now show the "killed" terminal state, not the form.
    page = client.get(f"/interrupts/{iid}").text
    assert "Killed" in page
    assert "Approve & Continue" not in page


def test_decide_invalid_value(client: TestClient) -> None:
    iid = _create(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "maybe"},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 400


def test_get_missing_interrupt_returns_404(client: TestClient) -> None:
    assert (
        client.get("/interrupts/does-not-exist/status", headers=SDK_HEADERS).status_code
        == 404
    )
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


# --- Auth on /interrupts creation (SDK secret) ----------------------------

def test_create_interrupt_requires_sdk_secret(client: TestClient) -> None:
    resp = client.post("/interrupts", json=_sample_payload())  # no header
    assert resp.status_code == 401


def test_create_interrupt_rejects_wrong_sdk_secret(client: TestClient) -> None:
    resp = client.post(
        "/interrupts", json=_sample_payload(), headers={"X-SDK-Secret": "nope"}
    )
    assert resp.status_code == 401


def test_status_requires_sdk_secret(client: TestClient) -> None:
    iid = _create(client)
    assert client.get(f"/interrupts/{iid}/status").status_code == 401
    assert (
        client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).status_code == 200
    )


# --- Auth on /decide (approver secret) ------------------------------------

def test_decide_rejects_request_without_approver_secret(client: TestClient) -> None:
    """The core fix: an interrupt cannot be approved without the approver secret."""
    iid = _create(client)
    resp = client.post(f"/interrupts/{iid}/decide", json={"decision": "approve"})
    assert resp.status_code == 403
    # The run stays pending — nothing was approved.
    assert (
        client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).json()["status"]
        == "pending"
    )


def test_decide_rejects_wrong_approver_secret(client: TestClient) -> None:
    iid = _create(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve"},
        headers={"X-Approver-Secret": "wrong"},
    )
    assert resp.status_code == 403


def test_sdk_secret_cannot_approve(client: TestClient) -> None:
    """An agent that holds the SDK secret still cannot approve its own interrupt.

    The SDK secret authorizes creation/polling only; /decide demands the
    separate approver secret, which the SDK process never possesses.
    """
    iid = _create(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve"},
        headers=SDK_HEADERS,  # the only secret the SDK has
    )
    assert resp.status_code == 403
    assert (
        client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).json()["status"]
        == "pending"
    )


def test_decide_accepts_approver_secret_via_query_token(client: TestClient) -> None:
    iid = _create(client)
    resp = client.post(
        f"/interrupts/{iid}/decide?token={APPROVER_SECRET}",
        json={"decision": "approve"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "approved"}


def test_html_view_does_not_leak_approver_secret(client: TestClient) -> None:
    """The agent knows the interrupt id and can GET the HTML page; that page
    must never contain the approver secret, or scraping it would defeat auth."""
    iid = _create(client)
    page = client.get(f"/interrupts/{iid}").text
    assert APPROVER_SECRET not in page
    assert SDK_SECRET not in page


# --- Approval is bound to the action (PIPE08 / ASI09) ---------------------
#
# An approval that names only a tool is not an approval. These cover the fix
# for approvers seeing "send_email" with no sight of `to=attacker@evil.com`.

PENDING_DIGEST = "sha256:" + "a" * 64


def _pending_payload(args: dict | None = None, digest: str = PENDING_DIGEST) -> dict:
    payload = _sample_payload()
    payload["reason"] = "FLOW"
    payload["context"]["tool"] = "send_email"
    payload["context"]["pending_call"] = {
        "tool": "send_email",
        "args": args if args is not None else {"to": "attacker@evil.com"},
        "args_digest": digest,
    }
    return payload


def _create_pending(client: TestClient, **kw) -> str:
    resp = client.post("/interrupts", json=_pending_payload(**kw), headers=SDK_HEADERS)
    assert resp.status_code == 200
    return resp.json()["interrupt_id"]


def test_approval_page_shows_the_pending_arguments(client: TestClient) -> None:
    """The approver must see what they are approving, not just its name."""
    iid = _create_pending(client)
    page = client.get(f"/interrupts/{iid}").text
    assert "attacker@evil.com" in page
    assert "Action awaiting your approval" in page
    assert PENDING_DIGEST in page


def test_pending_arguments_are_escaped_in_the_page(client: TestClient) -> None:
    """Pending args are attacker-controlled — rendering them must not inject.

    The whole point of the panel is to put untrusted arguments in front of a
    human, so it is exactly where an injected payload would pay off.
    """
    iid = _create_pending(client, args={"body": "<script>alert(1)</script>"})
    page = client.get(f"/interrupts/{iid}").text
    assert "<script>alert(1)</script>" not in page
    assert "alert(1)" in page  # displayed, but escaped


def test_approve_without_the_digest_is_refused(client: TestClient) -> None:
    iid = _create_pending(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve"},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 409
    # And the interrupt is untouched — still awaiting a real decision.
    assert client.get(f"/interrupts/{iid}/status", headers=SDK_HEADERS).json() == {
        "status": "pending"
    }


def test_approve_with_a_mismatched_digest_is_refused(client: TestClient) -> None:
    iid = _create_pending(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve", "args_digest": "sha256:" + "b" * 64},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 409


def test_approve_with_the_matching_digest_succeeds(client: TestClient) -> None:
    iid = _create_pending(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve", "args_digest": PENDING_DIGEST},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "approved"}


def test_kill_never_needs_the_digest(client: TestClient) -> None:
    """Stopping is safe under any reading of the request — never gate it."""
    iid = _create_pending(client)
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "kill"},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "killed"}


def test_interrupt_without_a_pending_call_still_approves(client: TestClient) -> None:
    """Older SDKs send no pending_call; binding must not break them."""
    iid = _create(client)  # _sample_payload has no pending_call
    resp = client.post(
        f"/interrupts/{iid}/decide",
        json={"decision": "approve"},
        headers=APPROVER_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "approved"}


def test_receipt_binds_the_approved_arguments(client: TestClient) -> None:
    """Two approvals differing only in pending args must not share a digest.

    Before the fix the receipt digested the *executed* call history, and the
    pending call — the one actually approved — was not in it, so both receipts
    came out identical.
    """
    digests = []
    for args in ({"to": "ok@example.com"}, {"to": "attacker@evil.com"}):
        iid = _create_pending(client, args=args)
        resp = client.post(
            f"/interrupts/{iid}/decide",
            json={"decision": "approve", "args_digest": PENDING_DIGEST},
            headers=APPROVER_HEADERS,
        )
        assert resp.status_code == 200
        att = client.get(f"/attestations/{iid}").json()["attestation"]
        digests.append(att["tool_args_digest"])
        assert att["info_summary"]["pending_tool"] == "send_email"

    assert digests[0] != digests[1]
