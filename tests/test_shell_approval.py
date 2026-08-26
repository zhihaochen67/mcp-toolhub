"""End-to-end tests for the shell approval flow."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from toolhub.security import approval
from toolhub.security.approval import ApprovalStatus
from toolhub.security.executable_snapshot import resolve_executable_snapshot
from toolhub.security.paths import (
    _reset_workspace_configuration_for_tests,
    get_workspace_root,
    resolve_workspace_path,
)
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
    payload = dict(defaults.pop("payload", {}))
    working_directory = resolve_workspace_path(defaults["cwd"])
    snapshot = resolve_executable_snapshot(
        defaults["program"],
        working_directory=working_directory,
    )
    payload.setdefault("workspace_root", str(get_workspace_root()))
    payload.setdefault("executable_snapshot", snapshot.to_payload())
    defaults["payload"] = payload
    return approval.create_request(**defaults)


def _make_executable(directory: Path, stem: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if os.name == "nt" else ""
    path = directory / f"{stem}{suffix}"
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.resolve()


def test_low_python_version_executes():
    result = run_shell("python", ["--version"])

    assert result.executed is True
    assert result.returncode == 0
    assert "Python" in result.stdout
    assert result.risk == RiskLevel.LOW
    assert result.request_id is None
    assert result.approval_status is None


def test_low_execution_does_not_start_a_subprocess(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Python 3.13.11\n", stderr=""
        )

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)

    result = run_shell("python", ["--version"])

    assert result.executed is True
    assert result.returncode == 0
    assert result.stdout.startswith("Python ")
    assert calls == []


def test_generic_git_status_requires_approval():
    result = run_shell("git", ["status"])

    assert result.executed is False
    assert result.risk == RiskLevel.HIGH
    assert result.approval_status == ApprovalStatus.PENDING
    assert result.request_id is not None
    assert "Generic Git" in result.risk_reason


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
    snapshot = request.payload["executable_snapshot"]
    assert cmd == [snapshot["canonical_path"], "--version"]
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == get_workspace_root()


def test_path_change_after_approval_does_not_change_executable(
    temp_dir,
    monkeypatch,
):
    first = _make_executable(temp_dir / "first", "bound-tool", "first")
    second = _make_executable(temp_dir / "second", "bound-tool", "second")
    monkeypatch.setenv("PATH", str(first.parent))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".EXE")

    created = run_shell("bound-tool", ["--probe"])
    stored = approval.get_request(created.request_id)
    assert stored.payload["executable_snapshot"]["canonical_path"] == str(first)
    approval.approve_request(created.request_id)
    monkeypatch.setenv("PATH", str(second.parent))

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="first\n", stderr="")

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)
    result = run_approved_shell(created.request_id)

    assert result.executed is True
    assert calls[0][0][0] == str(first)
    assert calls[0][0][0] != str(second)


def test_workspace_local_executable_runs_approved_identity(
    temp_dir,
    monkeypatch,
):
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir))
    _reset_workspace_configuration_for_tests()
    executable = _make_executable(temp_dir, "workspace-tool", "approved")
    created = run_shell(str(executable), ["--probe"])
    approval.approve_request(created.request_id)

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)
    result = run_approved_shell(created.request_id)

    assert result.executed is True
    assert calls[0][0] == [str(executable), "--probe"]
    assert calls[0][1]["cwd"] == temp_dir


def test_executable_replacement_after_approval_fails_closed(
    temp_dir,
    monkeypatch,
):
    executable = _make_executable(temp_dir, "replace-me", "approved")
    created = run_shell(str(executable), ["--probe"])
    approval.approve_request(created.request_id)
    executable.write_text("replacement", encoding="utf-8")

    calls = []
    monkeypatch.setattr(
        "toolhub.tools.shell.subprocess.run",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    result = run_approved_shell(created.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert "content changed" in result.message
    assert calls == []


def test_approved_request_without_executable_snapshot_fails_closed():
    request = approval.create_request(
        program=sys.executable,
        args=["--version"],
        cwd=".",
        risk=RiskLevel.MEDIUM,
        risk_reason="legacy test",
        payload={"workspace_root": str(get_workspace_root())},
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert "no executable snapshot" in result.message


def test_unresolved_executable_creates_no_approval():
    with pytest.raises(
        ValueError,
        match="could not be resolved at approval creation",
    ):
        run_shell("toolhub-command-that-does-not-exist", ["--probe"])

    assert approval.list_requests() == []


def test_workspace_path_security_still_works():
    with pytest.raises(ValueError):
        resolve_workspace_path("../escape.txt")

    with pytest.raises(ValueError):
        run_shell("python", ["--version"], cwd="../")
