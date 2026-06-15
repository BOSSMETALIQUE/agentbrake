"""Shared-secret authentication for the AgentBrake backend.

Two *distinct* secrets enforce a privilege boundary the SDK process must not
cross:

* **SDK secret** — lets a caller CREATE interrupts and POLL status. The SDK,
  and therefore the guarded agent's own process, holds this.
* **Approver secret** — lets a caller DECIDE (approve / kill) an interrupt.
  The SDK must NEVER possess this; only a human, via the validation UI served
  by the trusted backend, supplies it.

The whole point of remote mode is to stop an agent from waving through its own
interruption. If the agent could approve, the brake would be self-releasing —
useless for exactly the agents dangerous enough to need it. Keeping the
approver secret out of the SDK/agent process is what makes the
human-in-the-loop real.

Each secret is taken from its env var if set, otherwise generated at startup.
A generated secret is printed to the SERVER's own console (see
``startup_banner``) and never returned to the SDK or embedded in any
agent-reachable response.
"""

from __future__ import annotations

import os
import secrets
from typing import Optional, Tuple

from fastapi import Header, HTTPException, Query

SDK_SECRET_ENV = "AGENTBRAKE_SDK_SECRET"
APPROVER_SECRET_ENV = "AGENTBRAKE_APPROVER_SECRET"


def _resolve(env_name: str) -> Tuple[str, bool]:
    """Return (secret, from_env). Generates a strong random secret if unset."""
    configured = os.environ.get(env_name)
    if configured:
        return configured, True
    return secrets.token_urlsafe(32), False


SDK_SECRET, SDK_SECRET_FROM_ENV = _resolve(SDK_SECRET_ENV)
APPROVER_SECRET, APPROVER_SECRET_FROM_ENV = _resolve(APPROVER_SECRET_ENV)


def _matches(presented: Optional[str], expected: str) -> bool:
    """Constant-time comparison; a missing/empty value never matches."""
    if not presented:
        return False
    return secrets.compare_digest(presented, expected)


def require_sdk_secret(x_sdk_secret: Optional[str] = Header(default=None)) -> None:
    """Gate the endpoints the SDK calls: POST /interrupts and GET /status.

    Stops anyone who merely finds the URL from spamming forged interrupt
    records or enumerating run status.
    """
    # Module-global lookups happen at call time, so tests can monkeypatch
    # security.SDK_SECRET and this dependency picks up the new value.
    if not _matches(x_sdk_secret, SDK_SECRET):
        raise HTTPException(
            status_code=401,
            detail=f"missing or invalid SDK secret (set {SDK_SECRET_ENV})",
        )


def require_approver_secret(
    x_approver_secret: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> None:
    """Gate the privileged action: POST /decide.

    The SDK never holds the approver secret, so even though a guarded agent can
    *reach* this endpoint, it cannot satisfy this dependency. Accepted via the
    ``X-Approver-Secret`` header (used by the validation UI's fetch) or a
    ``?token=`` query param (so a human can paste a one-click link).
    """
    presented = x_approver_secret or token
    if not _matches(presented, APPROVER_SECRET):
        raise HTTPException(
            status_code=403,
            detail="missing or invalid approver secret",
        )


def startup_banner() -> str:
    """Secret summary for the SERVER console only — never sent to the SDK."""
    lines = [
        "=" * 66,
        "  AgentBrake backend — shared secrets (shown on the server console)",
        "-" * 66,
    ]
    if SDK_SECRET_FROM_ENV:
        lines.append(f"  SDK secret:      from ${SDK_SECRET_ENV}")
    else:
        lines.append("  SDK secret:      generated — set this on the SDK side:")
        lines.append(f"      {SDK_SECRET_ENV}={SDK_SECRET}")
    if APPROVER_SECRET_FROM_ENV:
        lines.append(f"  Approver secret: from ${APPROVER_SECRET_ENV}  (KEEP PRIVATE)")
    else:
        lines.append("  Approver secret: generated — KEEP PRIVATE, never give to the SDK:")
        lines.append(f"      {APPROVER_SECRET}")
    lines.append("-" * 66)
    lines.append("  Approve/kill: open an interrupt with ?token=<approver secret>")
    lines.append("  or paste the secret into the validation page.")
    lines.append("=" * 66)
    return "\n".join(lines)
