"""End-to-end guard on the flagship demo: one command, whole pipeline.

Runs examples/06_verifiable_audit_trail.py as a real subprocess — the same
command a prospect copy-pastes — and asserts the pipeline held: attack
blocked, bundle verified, tampering caught, report produced. If any phase of
the receipt system regresses, this is the test that notices from the outside.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "06_verifiable_audit_trail.py"


def test_demo_runs_end_to_end(tmp_path):
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # The demo must not inherit a signing config from the developer's shell.
    for var in ("AGENTBRAKE_SIGNING_KEY", "AGENTBRAKE_SIGNING_KEY_FILE",
                "AGENTBRAKE_SIGNING_SEED"):
        env.pop(var, None)

    result = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=tmp_path,  # artifacts land in tmp_path/demo_output
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    out = result.stdout
    assert "BLOCKED send_email" in out
    assert "BLOCKED http_post" in out
    assert out.count("Verdict: VERIFIED") == 2  # full bundle + single receipt
    assert "Verdict: VERIFICATION FAILED" in out  # the tampered counter-test
    assert "DATA LEFT THE BUILDING" not in out  # nothing was exfiltrated

    out_dir = tmp_path / "demo_output"
    for name in (
        "receipts.jsonl",
        "receipts_export.json",
        "receipts_export.TAMPERED.json",
        "receipt_proof.json",
        "compliance_report.md",
        "public_key.hex",
    ):
        assert (out_dir / name).exists(), f"missing artifact {name}"

    report = (out_dir / "compliance_report.md").read_text(encoding="utf-8")
    assert "Evidence integrity: VERIFIED" in report
    assert "2** attack flow(s) blocked automatically" in report
