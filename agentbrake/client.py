"""Sync HTTP client for the AgentBrake backend.

Sync (not async) on purpose: @guard() wraps an arbitrary user function that
may be sync, and forcing the user to add an event loop just to be paused for
human review would be hostile. We use httpx.Client and short polling.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional, Tuple

import httpx


class AgentBrakeClient:
    """Thin HTTP client for the FastAPI backend.

    SECURITY: this client only ever CREATES interrupts and POLLS status. It
    holds the *SDK* secret (``AGENTBRAKE_SDK_SECRET``) and nothing more. It has
    no approver secret and deliberately exposes no approve/decide method — the
    guarded agent runs in this process, so giving it the means to approve its
    own interruption would defeat the human-in-the-loop. Approving is a
    server-side, human-only action gated by a separate approver secret.
    """

    def __init__(
        self,
        api_url: str,
        timeout: float = 10.0,
        sdk_secret: Optional[str] = None,
    ):
        self.api_url = api_url.rstrip("/")
        self.sdk_secret = (
            sdk_secret if sdk_secret is not None
            else os.environ.get("AGENTBRAKE_SDK_SECRET")
        )
        headers = {"X-SDK-Secret": self.sdk_secret} if self.sdk_secret else {}
        self._http = httpx.Client(base_url=self.api_url, timeout=timeout, headers=headers)

    def submit_interrupt(
        self,
        run_id: str,
        reason: str,
        context: Dict[str, Any],
    ) -> Tuple[str, str]:
        """POST /interrupts. Returns (interrupt_id, validation_url)."""
        resp = self._http.post(
            "/interrupts",
            json={"run_id": run_id, "reason": reason, "context": context},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["interrupt_id"], data["validation_url"]

    def get_status(self, interrupt_id: str) -> str:
        resp = self._http.get(f"/interrupts/{interrupt_id}/status")
        resp.raise_for_status()
        return resp.json()["status"]

    def wait_for_decision(
        self,
        interrupt_id: str,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> str:
        """Poll until status leaves 'pending'. Returns 'approved' or 'killed'.

        Raises TimeoutError if the deadline passes while still pending.
        """
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_status(interrupt_id)
            if status != "pending":
                return status
            if time.monotonic() >= deadline:
                raise TimeoutError(f"interrupt {interrupt_id} still pending after {timeout}s")
            time.sleep(poll_interval)

    def close(self) -> None:
        self._http.close()
