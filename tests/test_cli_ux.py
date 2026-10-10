"""CLI ergonomics: --version, and verify output that never overclaims."""

from __future__ import annotations

import pytest

import agentbrake
from agentbrake import cli


def test_version_flag_prints_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"agentbrake {agentbrake.__version__}"
