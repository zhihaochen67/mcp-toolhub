"""Tests for the audit / trace subsystem and its shell integration."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.executable_snapshot import resolve_executable_snapshot
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.paths import (
    _reset_runtime_configuration_for_tests,
    get_state_root,
    get_workspace_root,
    resolve_workspace_path,
)
from mcp_toolhub.security.process_containment import (
    ContainedProcessResult,
    containment_policy_metadata,
)
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.tools.shell import run_approved_shell, run_shell


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
    payload.setdefault(
        "execution_environment", build_execution_environment().to_payload()
    )
    defaults["payload"] = payload
    return approval.create_request(**defaults)


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
    environment = event["extra"]["command_policy"]["execution_environment"]
    assert set(environment) == {"policy_version", "variable_count", "sha256"}


def test_audit_records_only_environment_metadata(monkeypatch):
    sentinel = "TOP-SECRET-CHILD-ENVIRONMENT-63c1"
    monkeypatch.setenv("TOOLHUB_TEST_SECRET_TOKEN", sentinel)

    result = run_shell("pytest", ["-q"])
    event = _last_event()
    raw = (get_state_root() / "audit.jsonl").read_text(encoding="utf-8")

    assert result.outcome == ContractOutcome.APPROVAL_REQUIRED
    metadata = event["extra"]["command_policy"]["execution_environment"]
    assert set(metadata) == {"policy_version", "variable_count", "sha256"}
    assert sentinel not in raw
    assert "variables" not in metadata


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

    def fake_run(*args, **kwargs):
        return _contained_result(stdout="clean\n")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)
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
    _reset_runtime_configuration_for_tests()
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


def test_high_approval_creates_audit_record(high_python_command):
    program, args = high_python_command

    result = run_shell(program, args)
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
    containment = event["extra"]["containment"]
    assert containment["policy_version"] == 1
    assert containment["platform"] in {"windows", "posix"}
    assert containment["mechanism"] in {"job_object", "session_process_group"}
    assert "pid" not in json.dumps(containment).lower()
    assert "handle" not in json.dumps(containment).lower()


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
    def fake_run(*args, **kwargs):
        return _contained_result(timed_out=True)

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

    request = _create_request(program="pytest", args=["-q"])
    approval.approve_request(request.request_id)
    result = run_approved_shell(request.request_id)
    assert result.executed is True
    assert result.timed_out is True
    assert result.outcome == ContractOutcome.TIMED_OUT
    assert result.error.code == "COMMAND_TIMED_OUT"

    event = _last_event()
    assert event["action"] == "timeout"
    assert event["executed"] is True
    assert event["success"] is False
    assert event["error_type"] == "TimeoutExpired"


def test_execution_failure_audited(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("no such executable")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

    request = _create_request(program="pytest", args=["-q"])
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)
    assert result.outcome == ContractOutcome.FAILED
    assert result.error.code == "COMMAND_START_FAILED"

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

    raw = (get_state_root() / "audit.jsonl").read_text(encoding="utf-8")
    assert "hunter2" not in raw
    assert "abc123" not in raw


def test_audit_failure_does_not_break_execution(isolated_approval_store):
    blocker = isolated_approval_store.parent / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    # The write path itself fails defensively...
    assert (
        audit.record_event(
            tool="test",
            action="x",
            audit_path=blocker / "audit.jsonl",
        )
        is False
    )

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

    from mcp_toolhub.tools.audit import register_audit_tools

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


def _raw_audit_lines(*indexes: int) -> list[bytes]:
    return [
        (
            json.dumps(
                {
                    "trace_id": f"trc_{index}",
                    "timestamp": f"2026-04-{index + 1:02d}T00:00:00+00:00",
                    "tool": "test",
                    "action": "compact",
                    "extra": {"index": index},
                },
                ensure_ascii=False,
                indent=None,
                separators=(", ", ": "),
            )
            + "\n"
        ).encode("utf-8")
        for index in indexes
    ]


def _wait_for_file(path: Path, *, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists()


def test_audit_lock_excludes_another_process(temp_dir):
    path = temp_dir / "audit.jsonl"
    outcome = temp_dir / "lock-outcome"
    contender_code = (
        "import sys; from pathlib import Path; "
        "from mcp_toolhub.observability import audit; "
        "path,outcome=map(Path,sys.argv[1:3]); "
        "audit.AUDIT_LOCK_TIMEOUT_SECONDS=0.2; "
        "\ntry:\n"
        " with audit._audit_write_lock(path): result='acquired'\n"
        "except TimeoutError: result='timeout'\n"
        "outcome.write_text(result,encoding='utf-8')"
    )

    with audit._audit_write_lock(path):
        subprocess.run(
            [sys.executable, "-c", contender_code, str(path), str(outcome)],
            cwd=Path.cwd(),
            check=True,
            timeout=10,
        )

    assert outcome.read_text(encoding="utf-8") == "timeout"


def test_audit_lock_waiter_acquires_after_owner_releases(temp_dir):
    path = temp_dir / "audit.jsonl"
    ready = temp_dir / "waiter-ready"
    entered = temp_dir / "waiter-entered"
    waiter_code = (
        "import sys; from pathlib import Path; "
        "from mcp_toolhub.observability import audit; "
        "path,ready,entered=map(Path,sys.argv[1:4]); "
        "ready.write_text('ready',encoding='utf-8'); "
        "\nwith audit._audit_write_lock(path):\n"
        " entered.write_text('entered',encoding='utf-8')"
    )
    process = None

    try:
        with audit._audit_write_lock(path):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    waiter_code,
                    str(path),
                    str(ready),
                    str(entered),
                ],
                cwd=Path.cwd(),
            )
            _wait_for_file(ready)
            time.sleep(0.2)
            assert entered.exists() is False
            assert process.poll() is None

        assert process.wait(timeout=10) == 0
        assert entered.read_text(encoding="utf-8") == "entered"
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_audit_lock_is_released_when_owner_process_terminates(
    temp_dir,
    monkeypatch,
):
    path = temp_dir / "audit.jsonl"
    acquired = temp_dir / "owner-acquired"
    owner_code = (
        "import sys,time; from pathlib import Path; "
        "from mcp_toolhub.observability import audit; "
        "path,acquired=map(Path,sys.argv[1:3]); "
        "\nwith audit._audit_write_lock(path):\n"
        " acquired.write_text('acquired',encoding='utf-8')\n"
        " while True: time.sleep(1)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", owner_code, str(path), str(acquired)],
        cwd=Path.cwd(),
    )

    try:
        _wait_for_file(acquired)
        process.terminate()
        assert process.wait(timeout=10) != 0
        assert path.with_name(path.name + ".lock").exists()

        monkeypatch.setattr(audit, "AUDIT_LOCK_TIMEOUT_SECONDS", 0.5)
        with audit._audit_write_lock(path):
            pass
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_audit_compaction_dry_run_does_not_mutate(temp_dir):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(b"".join(_raw_audit_lines(0, 1, 2)))
    before = path.read_bytes()

    result = audit.compact_audit(1, audit_path=path)

    assert result.removed == 2
    assert result.changed is False
    assert path.read_bytes() == before


def test_audit_compaction_keeps_newest_events_in_exact_original_form(temp_dir):
    path = temp_dir / "audit.jsonl"
    lines = _raw_audit_lines(0, 1, 2, 3)
    path.write_bytes(b"".join(lines))

    result = audit.compact_audit(2, apply=True, audit_path=path)

    assert result.total == 4
    assert result.retained == 2
    assert result.removed == 2
    assert result.changed is True
    assert path.read_bytes() == b"".join(lines[-2:])


def test_audit_compaction_keep_at_least_count_is_byte_exact_noop(temp_dir):
    path = temp_dir / "audit.jsonl"
    original = b"".join(_raw_audit_lines(0, 1))
    path.write_bytes(original)

    result = audit.compact_audit(2, apply=True, audit_path=path)

    assert result.removed == 0
    assert result.changed is False
    assert path.read_bytes() == original


def test_audit_compaction_keep_zero_empties_existing_log(temp_dir):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(b"".join(_raw_audit_lines(0, 1)))

    result = audit.compact_audit(0, apply=True, audit_path=path)

    assert result.retained == 0
    assert result.removed == 2
    assert path.read_bytes() == b""


def test_audit_compaction_missing_file_is_noop(temp_dir):
    path = temp_dir / "missing-audit.jsonl"

    result = audit.compact_audit(10, apply=True, audit_path=path)

    assert result.total == result.removed == result.retained == 0
    assert result.changed is False
    assert path.exists() is False


@pytest.mark.parametrize("keep_last", [-1, audit.MAX_COMPACTION_EVENTS + 1])
def test_audit_compaction_invalid_limit_does_not_mutate(temp_dir, keep_last):
    path = temp_dir / "audit.jsonl"
    original = b"".join(_raw_audit_lines(0, 1))
    path.write_bytes(original)

    with pytest.raises(ValueError):
        audit.compact_audit(keep_last, apply=True, audit_path=path)

    assert path.read_bytes() == original


def test_audit_compaction_malformed_content_fails_closed(temp_dir):
    path = temp_dir / "audit.jsonl"
    original = _raw_audit_lines(0)[0] + b'{"incomplete":\n'
    path.write_bytes(original)

    with pytest.raises(audit.AuditMaintenanceError):
        audit.compact_audit(1, apply=True, audit_path=path)

    assert path.read_bytes() == original


def test_concurrent_cross_process_append_is_not_lost_during_compaction(
    temp_dir,
    monkeypatch,
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(b"".join(_raw_audit_lines(0, 1, 2)))
    ready = temp_dir / "writer-ready"
    go = temp_dir / "writer-go"
    original_write = audit._write_compacted_audit
    process = None

    writer_code = (
        "import sys,time; from pathlib import Path; "
        "from mcp_toolhub.observability.audit import record_event; "
        "audit_path,ready,go=map(Path,sys.argv[1:4]); "
        "ready.write_text('ready',encoding='utf-8'); "
        "\nwhile not go.exists(): time.sleep(0.01)\n"
        "ok=record_event(tool='child',action='append',audit_path=audit_path); "
        "raise SystemExit(0 if ok else 3)"
    )

    def coordinated_write(compaction_path, retained_offset):
        nonlocal process
        process = subprocess.Popen(
            [sys.executable, "-c", writer_code, str(path), str(ready), str(go)],
            cwd=Path.cwd(),
        )
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        go.write_text("go", encoding="utf-8")
        time.sleep(0.2)
        assert process.poll() is None
        original_write(compaction_path, retained_offset)

    monkeypatch.setattr(audit, "_write_compacted_audit", coordinated_write)

    audit.compact_audit(1, apply=True, audit_path=path)
    assert process is not None
    assert process.wait(timeout=10) == 0

    events = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["trace_id"] for event in events[:-1]] == ["trc_2"]
    assert events[-1]["tool"] == "child"


def test_record_event_never_raises_when_audit_lock_fails(monkeypatch, temp_dir):
    @contextmanager
    def failed_lock(_path):
        raise TimeoutError("simulated audit lock failure")
        yield  # pragma: no cover

    monkeypatch.setattr(audit, "_audit_write_lock", failed_lock)

    assert (
        audit.record_event(
            tool="test",
            action="lock_failure",
            audit_path=temp_dir / "audit.jsonl",
        )
        is False
    )


def test_compact_audit_reports_lock_acquisition_failure(monkeypatch, temp_dir):
    @contextmanager
    def failed_lock(_path):
        raise TimeoutError("simulated audit lock failure")
        yield  # pragma: no cover

    monkeypatch.setattr(audit, "_audit_write_lock", failed_lock)

    with pytest.raises(
        audit.AuditMaintenanceError,
        match="could not acquire the audit lock",
    ):
        audit.compact_audit(
            1,
            apply=True,
            audit_path=temp_dir / "audit.jsonl",
        )
