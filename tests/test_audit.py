"""Tests for the audit / trace subsystem and its shell integration."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from toolhub.observability import audit
from toolhub.security import approval
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

    result = run_shell("python", ["--version"])
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

    with pytest.raises(ValueError, match="Executable not found"):
        run_shell("python", ["--version"])

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
