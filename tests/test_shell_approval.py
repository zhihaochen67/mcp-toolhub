"""End-to-end tests for the shell approval flow."""

from __future__ import annotations

import subprocess
from datetime import timedelta

import pytest

from toolhub.security import approval
from toolhub.security.approval import ApprovalStatus
from toolhub.security.paths import get_workspace_root, resolve_workspace_path
from toolhub.security.risk import RiskLevel
from toolhub.tools.shell import run_approved_shell, run_shell


def _create_request(**kwargs):
    defaults = {
        "program": "python",
        "args": ["--version"],
        "cwd": ".",
        "risk": RiskLevel.MEDIUM,
        "risk_reason": "test",
    }
    defaults.update(kwargs)
    return approval.create_request(**defaults)


def test_low_python_version_executes():
    result = run_shell("python", ["--version"])

    assert result.executed is True
    assert result.returncode == 0
    assert "Python" in result.stdout
    assert result.risk == RiskLevel.LOW
    assert result.request_id is None
    assert result.approval_status is None


def test_medium_pytest_creates_pending_request():
    result = run_shell("pytest", ["-q"])

    assert result.executed is False
    assert result.risk == RiskLevel.MEDIUM
    assert result.approval_status == ApprovalStatus.PENDING
    assert result.request_id is not None

    stored = approval.get_request(result.request_id)
    assert stored is not None
    assert stored.status == ApprovalStatus.PENDING
    assert stored.program == "pytest"
    assert stored.args == ["-q"]


def test_high_powershell_creates_pending_request():
    result = run_shell("powershell", ["-Command", "echo hi"])

    assert result.executed is False
    assert result.risk == RiskLevel.HIGH
    assert result.approval_status == ApprovalStatus.PENDING
    assert result.request_id is not None


def test_pending_cannot_run():
    created = run_shell("pytest", ["-q"])

    result = run_approved_shell(created.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.PENDING


def test_rejected_cannot_run():
    created = run_shell("pytest", ["-q"])
    approval.reject_request(created.request_id)

    result = run_approved_shell(created.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.REJECTED


def test_unknown_request_cannot_run():
    result = run_approved_shell("req_does_not_exist")

    assert result.executed is False
    assert result.approval_status is None


def test_approved_can_run():
    request = _create_request()
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is True
    assert result.returncode == 0
    assert "Python" in result.stdout
    assert result.approval_status == ApprovalStatus.CONSUMED


def test_approval_cannot_be_replayed():
    request = _create_request()
    approval.approve_request(request.request_id)

    first = run_approved_shell(request.request_id)
    assert first.executed is True

    second = run_approved_shell(request.request_id)
    assert second.executed is False
    assert second.approval_status == ApprovalStatus.CONSUMED


def test_expired_approval_cannot_run(monkeypatch):
    request = _create_request(ttl_seconds=10)
    approval.approve_request(request.request_id)

    future = request.expires_at + timedelta(seconds=5)
    monkeypatch.setattr("toolhub.security.approval._now", lambda: future)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.EXPIRED


def test_request_id_cannot_alter_command(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Python 3.13.11\n", stderr=""
        )

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)

    result = run_approved_shell(request.request_id)

    assert result.executed is True
    assert len(calls) == 1

    cmd, kwargs = calls[0]
    assert cmd == ["python", "--version"]
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == get_workspace_root()


def test_workspace_path_security_still_works():
    with pytest.raises(ValueError):
        resolve_workspace_path("../escape.txt")

    with pytest.raises(ValueError):
        run_shell("python", ["--version"], cwd="../")
