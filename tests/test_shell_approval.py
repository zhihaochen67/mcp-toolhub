"""End-to-end tests for the shell approval flow."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.executable_snapshot import resolve_executable_snapshot
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.paths import (
    _reset_runtime_configuration_for_tests,
    get_workspace_root,
    resolve_workspace_path,
)
from mcp_toolhub.security.process_containment import (
    ContainedProcessResult,
    containment_policy_metadata,
)
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.tools.shell import run_approved_shell, run_shell


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
    payload.setdefault(
        "execution_environment", build_execution_environment().to_payload()
    )
    defaults["payload"] = payload
    return approval.create_request(**defaults)


def _make_executable(directory: Path, stem: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if os.name == "nt" else ""
    path = directory / f"{stem}{suffix}"
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.resolve()


def _contained_result(
    returncode: int = 0,
    *,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> ContainedProcessResult:
    metadata = containment_policy_metadata()
    metadata.tree_termination_attempted = timed_out
    return ContainedProcessResult(
        returncode,
        stdout,
        stderr,
        timed_out,
        None,
        metadata,
    )


_DEFAULT_WORKSPACE = object()


def _create_shell_request_with_workspace(
    workspace_snapshot=_DEFAULT_WORKSPACE,
    *,
    cwd: str = ".",
):
    snapshot = resolve_executable_snapshot(
        sys.executable,
        working_directory=get_workspace_root(),
    )
    payload = {
        "executable_snapshot": snapshot.to_payload(),
        "execution_environment": build_execution_environment().to_payload(),
    }
    if workspace_snapshot is _DEFAULT_WORKSPACE:
        payload["workspace_root"] = str(get_workspace_root())
    elif workspace_snapshot is not None:
        payload["workspace_root"] = workspace_snapshot
    return approval.create_request(
        program=sys.executable,
        args=["--version"],
        cwd=cwd,
        risk=RiskLevel.MEDIUM,
        risk_reason="test",
        payload=payload,
    )


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

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return _contained_result(stdout="Python 3.13.11\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

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


def test_high_command_creates_pending_request(high_python_command):
    program, args = high_python_command

    result = run_shell(program, args)

    assert result.executed is False
    assert result.risk == RiskLevel.HIGH
    assert result.approval_status == ApprovalStatus.PENDING
    assert result.request_id is not None

    stored = approval.get_request(result.request_id)
    assert stored is not None
    assert stored.program == program
    assert stored.args == args
    assert stored.payload["executable_snapshot"]["canonical_path"] == str(
        Path(sys.executable).resolve()
    )
    assert len(stored.payload["executable_snapshot"]["sha256"]) == 64
    environment = stored.payload["execution_environment"]
    assert environment["policy_version"] == 1
    assert len(environment["sha256"]) == 64


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
    assert result.outcome == ContractOutcome.SUCCEEDED
    assert result.returncode == 0
    assert "Python" in result.stdout
    assert result.approval_status == ApprovalStatus.CONSUMED


def test_nonzero_approved_command_is_machine_readable(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)

    monkeypatch.setattr(
        "mcp_toolhub.tools.shell.run_contained_process",
        lambda *args, **kwargs: _contained_result(7, stderr="failed\n"),
    )

    result = run_approved_shell(request.request_id)

    assert result.outcome == ContractOutcome.COMMAND_FAILED
    assert result.error.code == "COMMAND_NONZERO_EXIT"
    assert result.returncode == 7
    assert result.approval_status == ApprovalStatus.CONSUMED


def test_approved_timeout_remains_machine_readable():
    request = _create_request(
        program=sys.executable,
        args=["-c", "import time; print('ready',flush=True); time.sleep(60)"],
        timeout_seconds=1,
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.outcome == ContractOutcome.TIMED_OUT
    assert result.error.code == "COMMAND_TIMED_OUT"
    assert result.executed is True
    assert result.timed_out is True
    assert "ready" in result.stdout
    assert result.approval_status == ApprovalStatus.CONSUMED


def test_approved_start_failure_remains_failed(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)

    def fail_start(*args, **kwargs):
        raise FileNotFoundError("simulated launch failure")

    monkeypatch.setattr(
        "mcp_toolhub.tools.shell.run_contained_process",
        fail_start,
    )
    result = run_approved_shell(request.request_id)

    assert result.outcome == ContractOutcome.FAILED
    assert result.error.code == "COMMAND_START_FAILED"
    assert result.executed is False
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
    monkeypatch.setattr("mcp_toolhub.security.approval._now", lambda: future)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.EXPIRED


def test_request_id_cannot_alter_command(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)

    calls = []

    def fake_run(executable, args, **kwargs):
        calls.append((executable, args, kwargs))
        return _contained_result(stdout="Python 3.13.11\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

    result = run_approved_shell(request.request_id)

    assert result.executed is True
    assert len(calls) == 1

    executable, called_args, kwargs = calls[0]
    snapshot = request.payload["executable_snapshot"]
    assert executable == snapshot["canonical_path"]
    assert called_args == ["--version"]
    assert kwargs["cwd"] == get_workspace_root()
    assert kwargs["env"] == request.payload["execution_environment"]["variables"]
    assert kwargs["timeout_seconds"] == request.timeout_seconds


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

    def fake_run(executable, args, **kwargs):
        calls.append((executable, args, kwargs))
        return _contained_result(stdout="first\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)
    result = run_approved_shell(created.request_id)

    assert result.executed is True
    assert calls[0][0] == str(first)
    assert calls[0][0] != str(second)


def test_workspace_local_executable_runs_approved_identity(
    temp_dir,
    monkeypatch,
):
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir))
    _reset_runtime_configuration_for_tests()
    executable = _make_executable(temp_dir, "workspace-tool", "approved")
    created = run_shell(str(executable), ["--probe"])
    approval.approve_request(created.request_id)

    calls = []

    def fake_run(executable, args, **kwargs):
        calls.append((executable, args, kwargs))
        return _contained_result(stdout="ok\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)
    result = run_approved_shell(created.request_id)

    assert result.executed is True
    assert calls[0][0] == str(executable)
    assert calls[0][1] == ["--probe"]
    assert calls[0][2]["cwd"] == temp_dir


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
        "mcp_toolhub.tools.shell.run_contained_process",
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
        payload={
            "workspace_root": str(get_workspace_root()),
            "execution_environment": build_execution_environment().to_payload(),
        },
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert "no executable snapshot" in result.message


def test_legacy_shell_approval_without_environment_snapshot_fails_closed():
    snapshot = resolve_executable_snapshot(
        sys.executable,
        working_directory=get_workspace_root(),
    )
    request = approval.create_request(
        program=sys.executable,
        args=["--version"],
        cwd=".",
        risk=RiskLevel.MEDIUM,
        risk_reason="legacy test",
        payload={
            "workspace_root": str(get_workspace_root()),
            "executable_snapshot": snapshot.to_payload(),
        },
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "EXECUTION_ENVIRONMENT_INVALID"
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED


def test_approved_child_uses_stored_sanitized_environment(monkeypatch):
    names = [
        "TOOLHUB_TEST_SECRET_TOKEN",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "NODE_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "BASH_ENV",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "PATH",
    ]
    first_secret = "toolhub-parent-secret-before-approval-91a4"
    second_secret = "toolhub-parent-secret-after-approval-2db7"
    for name in names:
        monkeypatch.setenv(name, first_secret)

    probe = (
        "import json, os; "
        f"names = {names!r}; "
        "print(json.dumps({name: os.environ.get(name) for name in names}, "
        "sort_keys=True))"
    )
    created = run_shell(sys.executable, ["-c", probe])
    stored = approval.get_request(created.request_id)
    stored_environment = stored.payload["execution_environment"]["variables"]

    assert first_secret not in created.model_dump_json()
    assert first_secret not in json.dumps(stored_environment)

    approval.approve_request(created.request_id)
    for name in names:
        monkeypatch.setenv(name, second_secret)

    result = run_approved_shell(created.request_id)
    observed = json.loads(result.stdout)

    assert result.outcome == ContractOutcome.SUCCEEDED
    assert observed == {name: None for name in names}
    assert first_secret not in result.model_dump_json()
    assert second_secret not in result.model_dump_json()


def test_resume_passes_exact_approved_environment_after_parent_changes(monkeypatch):
    request = _create_request()
    approved_environment = request.payload["execution_environment"]["variables"]
    approval.approve_request(request.request_id)
    monkeypatch.setenv("TEMP", r"C:\changed-after-approval")
    monkeypatch.setenv("TOOLHUB_TEST_SECRET_TOKEN", "new-parent-secret")
    calls = []

    def fake_run(executable, args, **kwargs):
        calls.append((executable, args, kwargs))
        return _contained_result(stdout="ok\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

    result = run_approved_shell(request.request_id)

    assert result.executed is True
    assert calls[0][2]["env"] == approved_environment
    assert "TOOLHUB_TEST_SECRET_TOKEN" not in calls[0][2]["env"]


@pytest.mark.parametrize(
    "malformed_environment",
    [
        None,
        {},
        {
            "policy_version": 1,
            "platform": "posix" if os.name != "nt" else "windows",
            "variables": {"PATH": "unapproved"},
            "sha256": "0" * 64,
        },
    ],
    ids=["missing", "missing-schema", "non-allowlisted"],
)
def test_malformed_environment_snapshot_fails_after_consumption(
    malformed_environment,
):
    request = _create_request(payload={"execution_environment": malformed_environment})
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "EXECUTION_ENVIRONMENT_INVALID"
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED


@pytest.mark.parametrize(
    "workspace_snapshot",
    [None, 123, "", "."],
    ids=["missing", "wrong-type", "empty", "relative"],
)
def test_invalid_workspace_snapshot_fails_after_consumption(workspace_snapshot):
    request = _create_shell_request_with_workspace(workspace_snapshot)
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert "workspace" in result.message.lower()
    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED


def test_mismatched_workspace_snapshot_is_consumed(temp_dir):
    request = _create_shell_request_with_workspace(str(temp_dir.resolve()))
    approval.approve_request(request.request_id)

    first = run_approved_shell(request.request_id)
    second = run_approved_shell(request.request_id)

    assert first.executed is False
    assert first.approval_status == ApprovalStatus.CONSUMED
    assert "different ToolHub workspace" in first.message
    assert second.executed is False
    assert second.approval_status == ApprovalStatus.CONSUMED


def test_nonexistent_workspace_snapshot_fails_strict_resolution():
    missing_root = get_workspace_root() / "missing-approved-workspace"
    request = _create_shell_request_with_workspace(str(missing_root))
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert "cannot be resolved" in result.message


@pytest.mark.parametrize(
    "cwd",
    ["\0", "../outside", "missing-directory"],
    ids=["malformed", "outside", "missing"],
)
def test_invalid_stored_cwd_fails_after_consumption(cwd):
    request = _create_shell_request_with_workspace(cwd=cwd)
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.CONSUMED
    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED


def test_wrong_approval_kind_is_not_consumed_by_shell():
    request = approval.create_request(
        kind="file_write",
        risk=RiskLevel.MEDIUM,
        risk_reason="test",
        payload={"workspace_root": str(get_workspace_root())},
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.APPROVED
    assert approval.get_request(request.request_id).status == ApprovalStatus.APPROVED


def test_concurrent_replay_allows_at_most_one_execution(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)
    barrier = threading.Barrier(2)
    original_consume = approval.consume_request
    executions = []
    execution_lock = threading.Lock()

    def synchronized_consume(request_id):
        barrier.wait(timeout=5)
        return original_consume(request_id)

    def fake_run(executable, args, **kwargs):
        with execution_lock:
            executions.append([executable, *args])
        return _contained_result(stdout="ok\n")

    monkeypatch.setattr(approval, "consume_request", synchronized_consume)
    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: run_approved_shell(request.request_id), range(2))
        )

    assert sum(result.executed for result in results) == 1
    assert len(executions) == 1
    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED


def test_executable_validation_is_the_final_identity_step(monkeypatch):
    request = _create_request()
    approval.approve_request(request.request_id)
    order = []

    from mcp_toolhub.tools import shell as shell_module

    original_validate = shell_module.validate_executable_snapshot

    def track_validation(payload):
        order.append("validate")
        return original_validate(payload)

    def fake_run(executable, args, **kwargs):
        order.append("launch")
        return _contained_result(stdout="ok\n")

    monkeypatch.setattr(shell_module, "validate_executable_snapshot", track_validation)
    monkeypatch.setattr(shell_module, "run_contained_process", fake_run)

    result = run_approved_shell(request.request_id)

    assert result.executed is True
    assert order == ["validate", "launch"]


def test_unresolved_executable_creates_no_approval():
    result = run_shell("toolhub-command-that-does-not-exist", ["--probe"])

    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "EXECUTABLE_RESOLUTION_FAILED"
    assert approval.list_requests() == []


def test_workspace_path_security_still_works():
    with pytest.raises(ValueError):
        resolve_workspace_path("../escape.txt")

    result = run_shell("python", ["--version"], cwd="../")
    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "WORKING_DIRECTORY_INVALID"
