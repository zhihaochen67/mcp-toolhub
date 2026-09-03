"""Focused coverage for Tool Execution Boundary Hardening V1."""

from __future__ import annotations

import hashlib
import io
import os
import sys
from pathlib import Path

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_toolhub.app import create_server
from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.paths import resolve_path_within
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.tools import filesystem as filesystem_tools
from mcp_toolhub.tools import git as git_tools
from mcp_toolhub.tools.filesystem import (
    _list_directory as list_directory,
)
from mcp_toolhub.tools.filesystem import (
    apply_patch,
    apply_patch_approved,
    read_file,
    write_file,
)
from mcp_toolhub.tools.git import _git_error, _RunGitResult, git_diff, git_status
from mcp_toolhub.tools.shell import (
    MAX_ARGUMENT_CHARS,
    MAX_ARGUMENTS,
    MAX_OUTPUT_CHARS,
    run_approved_shell,
    run_shell,
)


@pytest.mark.parametrize(
    "path",
    ["nested/../file.txt", r"nested\..\file.txt"],
    ids=["posix-syntax", "windows-syntax"],
)
def test_workspace_rejects_parent_components_even_when_normalized_inside(
    path, temp_dir
):
    with pytest.raises(ValueError, match="escapes workspace"):
        resolve_path_within(path, temp_dir)


@pytest.mark.parametrize("operation", [read_file, list_directory])
@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "nested/../file.txt",
        r"nested\..\file.txt",
        "/outside",
        "C:/outside",
        "C:outside",
        r"\\server\share\outside",
    ],
)
def test_filesystem_tools_reject_unsafe_paths(operation, path, temp_dir):
    with pytest.raises(ValueError, match="escapes workspace"):
        operation(path, root=temp_dir)


@pytest.mark.skipif(os.name != "nt", reason="Windows device and stream semantics")
@pytest.mark.parametrize("path", ["NUL", "con.txt", "dir/AUX", "COM1", "file:stream"])
def test_windows_device_and_stream_paths_are_rejected(path, temp_dir):
    with pytest.raises(ValueError, match="unsafe"):
        resolve_path_within(path, temp_dir)


def test_path_resolution_failure_is_redacted_and_chained(temp_dir, monkeypatch):
    target = temp_dir / "unresolvable"
    original_resolve = Path.resolve
    sentinel = "PRIVATE-RESOLUTION-DIAGNOSTIC"

    def fail_target(path, *args, **kwargs):
        if path == target:
            raise OSError(f"{sentinel}: {temp_dir}")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_target)
    with pytest.raises(ValueError, match="could not be resolved safely") as captured:
        resolve_path_within("unresolvable", temp_dir)
    assert isinstance(captured.value.__cause__, OSError)
    assert sentinel not in str(captured.value)
    assert str(temp_dir) not in str(captured.value)


def test_read_file_rejects_symlink_escape(temp_dir):
    outside = temp_dir.parent / f"{temp_dir.name}-outside.txt"
    link = temp_dir / "outside-link.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        os.symlink(outside, link)
    except (NotImplementedError, OSError) as exc:
        outside.unlink(missing_ok=True)
        pytest.skip(f"file symlinks are unavailable: {exc}")

    try:
        with pytest.raises(ValueError, match="escapes workspace"):
            read_file("outside-link.txt", root=temp_dir)
    finally:
        outside.unlink(missing_ok=True)


def test_directory_listing_has_a_hard_entry_bound(temp_dir, monkeypatch):
    for index in range(3):
        (temp_dir / f"file-{index}.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(filesystem_tools, "MAX_DIRECTORY_ENTRIES", 2)

    with pytest.raises(ValueError, match="too many entries"):
        list_directory(root=temp_dir)


def test_directory_listing_at_limit_is_sorted_and_non_recursive(temp_dir, monkeypatch):
    for name in ("b.txt", "a.txt"):
        (temp_dir / name).write_text("x", encoding="utf-8")
    (temp_dir / "child").mkdir()
    (temp_dir / "child" / "not-listed.txt").write_text("nested", encoding="utf-8")
    monkeypatch.setattr(filesystem_tools, "MAX_DIRECTORY_ENTRIES", 3)

    result = list_directory(root=temp_dir)

    assert result.path == "."
    assert [entry.name for entry in result.entries] == ["a.txt", "b.txt", "child"]


def test_read_uses_one_bounded_snapshot_even_if_file_grows(temp_dir, monkeypatch):
    target = temp_dir / "growing.txt"
    target.write_text("small", encoding="utf-8")
    monkeypatch.setattr(filesystem_tools, "MAX_FILE_SIZE", 8)
    original_open = Path.open
    requested_sizes = []

    class GrowingFile(io.BytesIO):
        def read(self, size=-1):
            requested_sizes.append(size)
            return super().read(size)

    def open_growing(path, *args, **kwargs):
        if path == target:
            return GrowingFile(b"x" * 100)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_growing)
    with pytest.raises(ValueError, match="File too large"):
        read_file("growing.txt", root=temp_dir)
    assert requested_sizes == [9]


def test_read_keeps_exact_byte_hash_and_legacy_newline_behavior(temp_dir):
    data = b"first\r\nsecond\rthird\n"
    (temp_dir / "newlines.txt").write_bytes(data)

    result = read_file("newlines.txt", root=temp_dir)

    assert result.content == "first\nsecond\nthird\n"
    assert result.size == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_read_failure_preserves_cause_without_exposing_canonical_path(
    temp_dir,
    monkeypatch,
):
    target = temp_dir / "denied.txt"
    target.write_text("content", encoding="utf-8")
    canonical = str(target.resolve())
    original_open = Path.open

    def deny_target(path, *args, **kwargs):
        if path == target.resolve():
            raise PermissionError(f"permission denied: {canonical}")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_target)

    with pytest.raises(ValueError, match="could not be read") as captured:
        read_file("denied.txt", root=temp_dir)

    assert isinstance(captured.value.__cause__, PermissionError)
    assert canonical not in str(captured.value)


def test_oversized_existing_file_is_refused_before_mutation(temp_dir, monkeypatch):
    monkeypatch.setattr(filesystem_tools, "MAX_FILE_SIZE", 4)
    target = temp_dir / "large.txt"
    target.write_text("12345", encoding="utf-8")

    result = write_file("large.txt", "new", root=temp_dir)

    assert result.outcome == ContractOutcome.REFUSED
    assert result.executed is False
    assert result.request_id is None
    assert target.read_text(encoding="utf-8") == "12345"


def test_oversized_patch_result_is_refused_before_mutation(temp_dir, monkeypatch):
    monkeypatch.setattr(filesystem_tools, "MAX_FILE_SIZE", 8)
    target = temp_dir / "bounded.txt"
    target.write_text("a\n", encoding="utf-8")
    patch = "--- a/bounded.txt\n+++ b/bounded.txt\n@@ -1 +1 @@\n-a\n+overflow\n"
    created = apply_patch("bounded.txt", patch, root=temp_dir)
    approval.approve_request(created.request_id)

    result = apply_patch_approved(created.request_id, root=temp_dir)

    assert result.outcome == ContractOutcome.CONFLICT
    assert result.executed is False
    assert target.read_text(encoding="utf-8") == "a\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO mutation target")
def test_special_file_mutation_is_refused_without_opening_fifo(temp_dir):
    os.mkfifo(temp_dir / "pipe")

    result = write_file("pipe", "replacement", root=temp_dir)

    assert result.outcome == ContractOutcome.REFUSED
    assert result.request_id is None
    assert "regular file" in result.message


def test_shell_rejects_oversized_command_material_without_approval():
    result = run_shell(sys.executable, ["x" * (MAX_ARGUMENT_CHARS + 1)])

    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "COMMAND_INPUT_INVALID"
    assert result.executed is False
    assert result.args == []
    assert approval.list_requests() == []


@pytest.mark.parametrize(
    ("program", "args", "timeout"),
    [
        ("", [], 20),
        ("python\0invalid", [], 20),
        ("python", ["invalid\0argument"], 20),
        ("python", [1], 20),
        ("python", "--version", 20),
        ("python", ["x"] * (MAX_ARGUMENTS + 1), 20),
        ("python", [], True),
        ("python", [], float("nan")),
    ],
    ids=[
        "empty-program",
        "nul-program",
        "nul-argument",
        "non-string-argument",
        "non-list-arguments",
        "argument-count",
        "boolean-timeout",
        "nonfinite-timeout",
    ],
)
def test_shell_refuses_malformed_command_before_approval(program, args, timeout):
    result = run_shell(program, args, timeout_seconds=timeout)

    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "COMMAND_INPUT_INVALID"
    assert result.executed is False
    assert result.request_id is None
    assert approval.list_requests() == []


def test_approved_malformed_command_is_consumed_without_execution():
    request = approval.create_request(
        program=sys.executable,
        args=["invalid\0argument"],
        risk=RiskLevel.HIGH,
        risk_reason="malformed command regression test",
    )
    approval.approve_request(request.request_id)

    result = run_approved_shell(request.request_id)

    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "COMMAND_INPUT_INVALID"
    assert result.executed is False
    assert result.approval_status == approval.ApprovalStatus.CONSUMED
    assert run_approved_shell(request.request_id).executed is False


def test_shell_timeout_after_oversized_output_preserves_contract():
    code = (
        "import sys,time; "
        "sys.stdout.buffer.write(b'x'*1048576);sys.stdout.flush(); "
        "sys.stderr.buffer.write(b'y'*1048576);sys.stderr.flush(); "
        "time.sleep(30)"
    )
    created = run_shell(sys.executable, ["-c", code], timeout_seconds=1)
    approval.approve_request(created.request_id)

    result = run_approved_shell(created.request_id)

    assert result.outcome == ContractOutcome.TIMED_OUT
    assert result.error.code == "COMMAND_TIMED_OUT"
    assert result.executed is True
    assert result.timed_out is True
    for stream, character in ((result.stdout, "x"), (result.stderr, "y")):
        assert stream.startswith(character * MAX_OUTPUT_CHARS)
        assert len(stream) < MAX_OUTPUT_CHARS + 100
        assert "output bytes]" in stream
    assert result.approval_status == approval.ApprovalStatus.CONSUMED


@pytest.mark.parametrize(
    "path",
    ["nested/../tracked.txt", r"nested\..\tracked.txt"],
    ids=["posix-syntax", "windows-syntax"],
)
def test_git_rejects_parent_components_even_when_normalized_inside(git_repo, path):
    with pytest.raises(ValueError, match="traversal"):
        git_diff(path=path, root=git_repo)


def test_git_failure_does_not_reflect_untrusted_stderr():
    secret_path = r"C:\sensitive\repository\private.txt"
    completed = _RunGitResult(
        returncode=2,
        stdout="",
        stderr=f"fatal: failed to read {secret_path}",
        stdout_truncated=False,
        stdout_dropped_bytes=0,
    )

    error = _git_error(completed)

    assert "git exited 2" in str(error)
    assert secret_path not in str(error)
    assert "fatal" not in str(error)


def test_git_parent_repository_rejection_does_not_leak_parent_path(git_repo):
    workspace = git_repo / "workspace"
    workspace.mkdir()

    with pytest.raises(ValueError, match="escapes ToolHub workspace") as captured:
        git_status(root=workspace)

    assert str(git_repo) not in str(captured.value)
    event = audit.read_recent(limit=10)[-1]
    assert event["error_type"] == "WorkspaceBoundaryViolation"
    assert str(git_repo) not in event["error"]


def test_git_status_limit_does_not_silently_return_partial_entries(monkeypatch):
    monkeypatch.setattr(git_tools, "GIT_MAX_STATUS_ENTRIES", 2)

    with pytest.raises(ValueError, match="too many entries"):
        git_tools._parse_status("## main\n?? a\n?? b\n?? c\n")


def test_dispatch_boundary_returns_bounded_path_failure():
    async def main():
        server = create_server()
        with pytest.raises(ToolError) as captured:
            await server.call_tool(
                "filesystem.read_file",
                {"path": "../outside.txt"},
            )
        assert "escapes workspace" in str(captured.value)
        assert str(Path.cwd().resolve()) not in str(captured.value)

    anyio.run(main)
