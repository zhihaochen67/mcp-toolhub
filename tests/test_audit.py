"""Tests for the audit / trace subsystem and its shell integration."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from toolhub.observability import audit
from toolhub.security import approval
from toolhub.security.executable_snapshot import resolve_executable_snapshot
from toolhub.security.paths import (
    _reset_workspace_configuration_for_tests,
    get_workspace_root,
    resolve_workspace_path,
)
from toolhub.security.risk import RiskLevel
from toolhub.tools.shell import run_approved_shell, run_shell


def _last_event():
    events = audit.read_recent(limit=100)
    assert events, "no audit events recorded"
    return events[-1]


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
    snapshot = resolve_executable_snapshot(
        defaults["program"],
        working_directory=resolve_workspace_path(defaults["cwd"]),
    )
    payload.setdefault("workspace_root", str(get_workspace_root()))
    payload.setdefault("executable_snapshot", snapshot.to_payload())
    defaults["payload"] = payload
    return approval.create_request(**defaults)


def test_low_execution_creates_audit_record():
    result = run_shell("python", ["--version"])
    assert result.executed is True

    event = _last_event()
    assert event["tool"] == "shell.run"
    assert event["action"] == "execute"
    assert event["risk"] == "LOW"
    assert event["executed"] is True
    assert event["success"] is True
    assert event["returncode"] == 0
    assert event["trace_id"].startswith("trc_")
    assert event["timestamp"]
    assert event["duration_ms"] >= 0
    assert event["stdout_chars"] > 0
    assert event["arguments"]["program"] == "python"
    assert event["arguments"]["args"] == ["--version"]
    policy = event["extra"]["command_policy"]
    assert policy["decision"] == "auto_execute"
    assert policy["profile"] == "python.version.long"
    assert policy["argument_shape"] == "python --version"
    assert policy["execution_kind"] == "intrinsic"
    assert policy["executable"]["trusted"] is True
    assert policy["executable"]["scope"] == "toolhub_runtime"
    assert "resolved_path" not in policy["executable"]


def test_medium_approval_creates_audit_record():
    result = run_shell("pytest", ["-q"])
    assert result.executed is False

    event = _last_event()
    assert event["tool"] == "shell.run"
    assert event["action"] == "approval_request"
    assert event["risk"] == "MEDIUM"
    assert event["approval_status"] == "PENDING"
    assert event["request_id"] == result.request_id
    assert event["executed"] is False
    assert event["success"] is True
    assert event["extra"]["command_policy"]["decision"] == "approval_required"


def test_generic_git_approval_audit_explains_policy():
    result = run_shell("git", ["status"])
    assert result.executed is False

    event = _last_event()
    policy = event["extra"]["command_policy"]
    assert policy["decision"] == "approval_required"
    assert policy["risk"] == "HIGH"
    assert policy["profile"] is None
    assert policy["executable"]["trusted"] is False
    assert "Generic Git" in policy["reason"]


def test_approved_execution_keeps_policy_audit_correlation(monkeypatch):
    created = run_shell("git", ["status"])
    approval.approve_request(created.request_id)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="clean\n", stderr="")

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)
    result = run_approved_shell(created.request_id)

    assert result.executed is True
    event = _last_event()
    assert event["action"] == "execute_approved"
    assert event["request_id"] == created.request_id
    assert event["extra"]["command_policy"]["decision"] == "approval_required"
    assert event["extra"]["command_policy"]["risk"] == "HIGH"


def _make_audit_executable(directory: Path, stem: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if os.name == "nt" else ""
    executable = directory / f"{stem}{suffix}"
    executable.write_text("audit executable", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable.resolve()


def test_external_executable_directory_is_not_exposed_in_policy_audit(
    temp_dir,
    monkeypatch,
):
    executable = _make_audit_executable(temp_dir / "private-bin", "audit-tool")
    monkeypatch.setenv("PATH", str(executable.parent))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".EXE")

    result = run_shell("audit-tool", ["--probe"])

    event = _last_event()
    identity = event["extra"]["command_policy"]["approval_executable"]
    stored = approval.get_request(result.request_id)
    snapshot = stored.payload["executable_snapshot"]
    assert identity["scope"] == "external"
    assert identity["resolved_name"] == executable.name
    assert identity["sha256"] == snapshot["sha256"]
    assert identity["size"] == snapshot["size"]
    assert result.request_id == event["request_id"]
    assert str(executable.parent) not in json.dumps(event)
    assert "canonical_path" not in json.dumps(identity)


def test_workspace_executable_audit_uses_relative_path(temp_dir, monkeypatch):
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir))
    _reset_workspace_configuration_for_tests()
    executable = _make_audit_executable(temp_dir / "tools", "workspace-audit")
    relative_program = str(executable.relative_to(temp_dir))

    run_shell(relative_program, ["--probe"])

    event = _last_event()
    identity = event["extra"]["command_policy"]["approval_executable"]
    assert identity["scope"] == "workspace"
    assert identity["workspace_path"] == executable.relative_to(temp_dir).as_posix()
    assert str(temp_dir) not in json.dumps(identity)


def test_audit_metadata_remains_bounded():
    audit.record_event(
        tool="bounded",
        action="metadata",
        extra={"items": ["x" * 500 for _ in range(50)]},
    )

    items = _last_event()["extra"]["items"]
    assert len(items) == audit.MAX_COLLECTION_ITEMS + 1
    assert all(len(item) <= audit.MAX_STRING_CHARS + 32 for item in items)


def test_high_approval_creates_audit_record():
    result = run_shell("powershell", ["-Command", "echo hi"])
    assert result.executed is False

    event = _last_event()
    assert event["tool"] == "shell.run"
    assert event["action"] == "approval_request"
    assert event["risk"] == "HIGH"
    assert event["approval_status"] == "PENDING"
    assert event["request_id"] == result.request_id


def test_approved_execution_creates_audit_record():
    request = _create_request()
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)
    assert result.executed is True

    event = _last_event()
    assert event["tool"] == "shell.run_approved"
    assert event["action"] == "execute_approved"
    assert event["approval_status"] == "CONSUMED"
    assert event["request_id"] == request.request_id
    assert event["executed"] is True
    assert event["success"] is True
    assert event["returncode"] == 0


def test_replay_attempt_audited():
    request = _create_request()
    approval.approve_request(request.request_id)
    run_approved_shell(request.request_id)

    second = run_approved_shell(request.request_id)
    assert second.executed is False

    event = _last_event()
    assert event["tool"] == "shell.run_approved"
    assert event["action"] == "approval_rejected"
    assert event["approval_status"] == "CONSUMED"
    assert event["executed"] is False
    assert event["success"] is False


def test_pending_and_rejected_attempts_audited():
    created = run_shell("pytest", ["-q"])

    run_approved_shell(created.request_id)
    event = _last_event()
    assert event["action"] == "approval_rejected"
    assert event["approval_status"] == "PENDING"

    approval.reject_request(created.request_id)
    run_approved_shell(created.request_id)
    event = _last_event()
    assert event["action"] == "approval_rejected"
    assert event["approval_status"] == "REJECTED"


def test_unknown_request_attempt_audited():
    run_approved_shell("req_does_not_exist")

    event = _last_event()
    assert event["action"] == "approval_rejected"
    # Not applicable: no request exists, so the field is absent.
    assert event.get("approval_status") is None
    assert event["error_type"] == "KeyError"


def test_timeout_audited(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)

    request = _create_request(program="pytest", args=["-q"])
    approval.approve_request(request.request_id)
    result = run_approved_shell(request.request_id)
    assert result.executed is True
    assert result.timed_out is True

    event = _last_event()
    assert event["action"] == "timeout"
    assert event["executed"] is True
    assert event["success"] is False
    assert event["error_type"] == "TimeoutExpired"


def test_execution_failure_audited(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("no such executable")

    monkeypatch.setattr("toolhub.tools.shell.subprocess.run", fake_run)

    request = _create_request(program="pytest", args=["-q"])
    approval.approve_request(request.request_id)

    with pytest.raises(ValueError, match="Executable not found"):
        run_approved_shell(request.request_id)

    event = _last_event()
    assert event["action"] == "failure"
    assert event["executed"] is False
    assert event["success"] is False
    assert event["error_type"] == "FileNotFoundError"
    assert "error" in event


def test_audit_redacts_sensitive_args():
    run_shell(
        "python",
        ["--password", "hunter2", "--token=abc123", "--version"],
    )

    event = _last_event()
    assert event["arguments"]["args"] == [
        "--password",
        "***",
        "--token=***",
        "--version",
    ]

    raw = Path(os.environ["TOOLHUB_AUDIT_PATH"]).read_text(encoding="utf-8")
    assert "hunter2" not in raw
    assert "abc123" not in raw


def test_audit_failure_does_not_break_execution(monkeypatch, isolated_approval_store):
    blocker = isolated_approval_store.parent / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("TOOLHUB_AUDIT_PATH", str(blocker / "audit.jsonl"))

    # The write path itself fails defensively...
    assert audit.record_event(tool="test", action="x") is False

    # ...and tool execution is unaffected.
    result = run_shell("python", ["--version"])
    assert result.executed is True
    assert result.returncode == 0


def test_trace_ids_unique_and_unpredictable():
    ids = {audit.new_trace_id() for _ in range(50)}
    assert len(ids) == 50
    for trace_id in ids:
        assert trace_id.startswith("trc_")
        assert len(trace_id) > 16


def test_audit_event_schema():
    run_shell("python", ["--version"])

    event = _last_event()
    for field in ("trace_id", "timestamp", "tool", "action", "executed", "success"):
        assert field in event


def test_read_recent_bounded():
    for index in range(120):
        audit.record_event(tool="t", action="a", extra={"i": index})

    events = audit.read_recent(limit=1000)
    assert len(events) == 100
    assert events[-1]["extra"]["i"] == 119

    events5 = audit.read_recent(limit=5)
    assert len(events5) == 5
    assert events5[-1]["extra"]["i"] == 119


def test_read_recent_empty_when_no_events():
    assert audit.read_recent(limit=10) == []


def test_audit_recent_tool_schema_and_reads():
    import anyio
    from mcp.server import MCPServer

    from toolhub.tools.audit import register_audit_tools

    run_shell("python", ["--version"])

    srv = MCPServer("test")
    register_audit_tools(srv)

    async def main():
        tools = await srv.list_tools()
        tool = next(t for t in tools if t.name == "toolhub.audit_recent")
        # Read-only API: only a "limit" parameter, no file access.
        assert list(tool.input_schema.get("properties", {}).keys()) == ["limit"]
        assert tool.annotations.read_only_hint is True

        result = await srv.call_tool("toolhub.audit_recent", {"limit": 5})
        content = result.structured_content
        assert content["count"] >= 1
        assert content["events"][-1]["tool"] == "shell.run"
        assert len(content["events"]) <= 5

    anyio.run(main)
