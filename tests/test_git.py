"""Tests for the dedicated read-only Git tools."""

from __future__ import annotations

import ctypes
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.process_containment import (
    ContainedProcessResult,
    containment_policy_metadata,
    run_contained_process,
)
from mcp_toolhub.tools.git import GIT_TIMEOUT_SECONDS, git_diff, git_status


def _write(repo, name, content):
    (repo / name).write_text(content, encoding="utf-8")


def _git(repo, *args):
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )


def _raw_status(repo):
    return subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _process_exists(pid: int) -> bool:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x00100000 | 0x00001000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x00000102
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _rmtree_readonly(path):
    """Remove a tree, clearing Windows read-only attributes (git sets them)."""

    def remove_readonly(func, failed_path, _exc_info):
        try:
            os.chmod(failed_path, stat.S_IWRITE)
            func(failed_path)
        except OSError:
            pass

    shutil.rmtree(path, onerror=remove_readonly)


def test_git_status_in_temp_repo(git_repo):
    _write(git_repo, "a.txt", "hello")

    result = git_status(root=git_repo)

    assert result.path == "."
    assert result.branch is not None
    assert result.clean is False
    assert any(entry.code == "??" and entry.path == "a.txt" for entry in result.entries)
    assert "a.txt" in result.raw


def test_git_diff_unstaged_change(git_repo):
    _write(git_repo, "a.txt", "one\n")
    _git(git_repo, "add", "a.txt")
    _write(git_repo, "a.txt", "one\ntwo\n")

    result = git_diff(root=git_repo)

    assert result.staged is False
    assert result.path is None
    assert result.binary is False
    assert result.additions == 1
    assert result.deletions == 0
    assert "+two" in result.raw


def test_git_diff_staged(git_repo):
    _write(git_repo, "a.txt", "one\n")
    _git(git_repo, "add", "a.txt")

    result = git_diff(staged=True, root=git_repo)

    assert result.staged is True
    assert result.additions == 1
    assert "+one" in result.raw


def test_git_diff_path_filter(git_repo):
    _write(git_repo, "a.txt", "one\n")
    _write(git_repo, "b.txt", "two\n")
    _git(git_repo, "add", "a.txt", "b.txt")
    _write(git_repo, "a.txt", "one\nA\n")
    _write(git_repo, "b.txt", "two\nB\n")

    result = git_diff(path="a.txt", root=git_repo)

    assert result.path == "a.txt"
    assert "a.txt" in result.raw
    assert "b.txt" not in result.raw


def test_git_diff_path_traversal_rejected(git_repo):
    with pytest.raises(ValueError, match="escapes"):
        git_diff(path="../outside.txt", root=git_repo)


def test_git_diff_posix_absolute_path_rejected(git_repo):
    with pytest.raises(ValueError, match="Absolute"):
        git_diff(path="/etc/passwd", root=git_repo)


@pytest.mark.parametrize(
    "path",
    [
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:Windows\\win.ini",
    ],
    ids=["drive-forward-slash", "drive-backslash", "drive-relative"],
)
def test_git_diff_windows_drive_path_rejected(git_repo, path):
    with pytest.raises(ValueError, match="Absolute"):
        git_diff(path=path, root=git_repo)


@pytest.mark.parametrize(
    "path",
    [
        "\\\\server\\share\\file",
        "//server/share/file",
        "\\Windows\\win.ini",
    ],
    ids=["unc-backslash", "unc-forward-slash", "rooted-backslash"],
)
def test_git_diff_windows_unc_or_rooted_path_rejected(git_repo, path):
    with pytest.raises(ValueError, match="Absolute"):
        git_diff(path=path, root=git_repo)


def test_git_tools_accept_no_arbitrary_arguments():
    import anyio
    from mcp.server import MCPServer

    from mcp_toolhub.tools.git import register_git_tools

    srv = MCPServer("test")
    register_git_tools(srv)

    async def main():
        tools = {t.name: t for t in await srv.list_tools()}

        status_props = tools["git.status"].input_schema.get("properties", {})
        diff_props = tools["git.diff"].input_schema.get("properties", {})

        assert set(status_props) == set()
        assert set(diff_props) == {"path", "staged"}

        assert tools["git.status"].annotations.read_only_hint is True
        assert tools["git.diff"].annotations.read_only_hint is True

    anyio.run(main)


def test_git_status_does_not_inherit_parent_git_ceiling(temp_dir, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(temp_dir.parent))

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_status(root=temp_dir)

    event = audit.read_recent(limit=10)[-1]
    assert event["tool"] == "git.status"
    assert event["action"] == "failure"
    assert event["error_type"] == "WorkspaceBoundaryViolation"


def test_git_diff_does_not_inherit_parent_git_ceiling(temp_dir, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(temp_dir.parent))

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_diff(root=temp_dir)


def test_git_tools_do_not_modify_repo(git_repo):
    _write(git_repo, "a.txt", "one\n")
    _git(git_repo, "add", "a.txt")
    _write(git_repo, "a.txt", "one\ntwo\n")

    index_before = (git_repo / ".git" / "index").read_bytes()
    head_before = (git_repo / ".git" / "HEAD").read_bytes()
    status_before = _raw_status(git_repo)
    entries_before = sorted(p.name for p in (git_repo / ".git").iterdir())

    git_status(root=git_repo)
    git_diff(root=git_repo)
    git_diff(staged=True, root=git_repo)
    git_diff(path="a.txt", root=git_repo)

    assert (git_repo / ".git" / "index").read_bytes() == index_before
    assert (git_repo / ".git" / "HEAD").read_bytes() == head_before
    assert sorted(p.name for p in (git_repo / ".git").iterdir()) == entries_before
    assert _raw_status(git_repo) == status_before


def test_git_tools_use_hardened_invocation(monkeypatch, git_repo):
    from mcp_toolhub.tools import git as git_tools

    calls = []

    def fake_run(executable, args, **kwargs):
        command = [executable, *args]
        calls.append((command, kwargs))
        returncode = 0
        if "--show-toplevel" in command:
            stdout = f"{git_repo}\n"
        else:
            stdout = ""
            if "config" in command or "--verify" in command:
                returncode = 1  # No filters and an unborn HEAD.
        return ContainedProcessResult(
            returncode,
            stdout,
            "",
            False,
            None,
            containment_policy_metadata(),
        )

    monkeypatch.setattr(git_tools, "run_contained_process", fake_run)

    git_status(root=git_repo)
    git_diff(root=git_repo)

    global_args = [
        "--no-optional-locks",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
    ]
    git_executable = str(Path(shutil.which("git")).resolve())
    rev_parse_cmd = [git_executable, *global_args, "rev-parse", "--show-toplevel"]

    assert len(calls) == 10
    assert calls[0][0] == rev_parse_cmd
    assert calls[4][0] == [
        git_executable,
        *global_args,
        "status",
        "--porcelain=v1",
        "--branch",
    ]
    assert calls[5][0] == rev_parse_cmd
    assert calls[9][0] == [
        git_executable,
        *global_args,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
    ]

    for offset in (0, 5):
        assert calls[offset + 1][0] == [
            git_executable,
            *global_args,
            "config",
            "--includes",
            "--null",
            "--get-regexp",
            git_tools._FILTER_CONFIG_PATTERN,
        ]
        assert calls[offset + 2][0] == [
            git_executable,
            *global_args,
            "ls-files",
            "--stage",
            "-z",
        ]
        assert calls[offset + 3][0] == [
            git_executable,
            *global_args,
            "rev-parse",
            "--verify",
            "--quiet",
            "HEAD",
        ]

    for command, kwargs in calls:
        assert command[1:5] == global_args
        assert kwargs["cwd"] == git_repo
        assert 0 < kwargs["timeout_seconds"] <= GIT_TIMEOUT_SECONDS

        env = kwargs["env"]
        assert env["GIT_OPTIONAL_LOCKS"] == "0"
        assert env["GIT_NO_LAZY_FETCH"] == "1"
        assert env["GIT_ALLOW_PROTOCOL"] == ""
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_PAGER"] == "cat"
        assert "PATH" not in env
        assert "PYTHONPATH" not in env
        assert "NODE_OPTIONS" not in env


def test_git_timeout_terminates_controlled_helper_child(monkeypatch, git_repo):
    from mcp_toolhub.tools import git as git_tools

    pid_file = git_repo / "git-helper-child.pid"
    child = "import time; time.sleep(60)"
    parent = (
        "import subprocess,sys,time; from pathlib import Path; "
        f"p=subprocess.Popen([sys.executable,'-c',{child!r}],"
        "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
        "Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii'); "
        "print('git-helper-ready',flush=True); time.sleep(60)"
    )

    def controlled_timeout(*args, **kwargs):
        return run_contained_process(
            sys.executable,
            ["-c", parent, str(pid_file)],
            cwd=git_repo,
            env=build_execution_environment().environment(),
            timeout_seconds=0.75,
        )

    monkeypatch.setattr(git_tools, "run_contained_process", controlled_timeout)

    with pytest.raises(TimeoutError, match="timed out"):
        git_tools._run_git(git_repo, ["status", "--porcelain=v1"])

    pid = int(pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 3
    while _process_exists(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_exists(pid), (
        "Contained Git helper child remained alive after timeout."
    )


def test_git_status_does_not_execute_repo_fsmonitor(git_repo):
    # A repository with core.fsmonitor enabled makes plain `git status`
    # spawn the fsmonitor daemon process, which leaves a marker directory
    # inside .git. The hardened tool must never do that.
    capability = subprocess.run(
        ["git", "fsmonitor--daemon", "status"],
        cwd=git_repo,
        env={**os.environ, "LC_ALL": "C"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    diagnostic = capability.stderr.lower()
    if "not supported on this platform" in diagnostic or (
        "fsmonitor--daemon" in diagnostic and "not a git command" in diagnostic
    ):
        # The separate hook-path regression still runs on these installations.
        pytest.skip("installed Git lacks built-in fsmonitor daemon support")

    _write(git_repo, "a.txt", "hello")
    _git(git_repo, "add", "a.txt")
    _git(git_repo, "config", "core.fsmonitor", "true")

    git_dir = git_repo / ".git"
    marker = git_dir / "fsmonitor--daemon"

    assert not marker.exists()

    # Prove the trigger is live: unhardened git status starts the daemon.
    subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=str(git_repo),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert marker.exists(), "plain git status should have started fsmonitor"

    # Shut the daemon down (ignore failure if it already exited) and remove
    # its marker directory so we start from a clean baseline.
    try:
        subprocess.run(
            ["git", "fsmonitor--daemon", "stop"],
            cwd=str(git_repo),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        pass
    _rmtree_readonly(marker)
    assert not marker.exists()

    entries_before = sorted(p.name for p in git_dir.iterdir())

    result = git_status(root=git_repo)
    assert result.clean is False

    assert not marker.exists(), "git.status must not execute repository fsmonitor"
    assert sorted(p.name for p in git_dir.iterdir()) == entries_before


def test_git_status_ignores_fsmonitor_hook_path(git_repo):
    # core.fsmonitor pointing at an external script: the tool must not
    # execute that program either.
    _write(git_repo, "a.txt", "hello")
    _git(git_repo, "add", "a.txt")

    marker = git_repo / "fsmonitor-hook-ran.marker"
    hook = git_repo / "fake-fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\necho ran > '{marker.as_posix()}'\nexit 0\n")
    _git(git_repo, "config", "core.fsmonitor", str(hook))

    result = git_status(root=git_repo)
    assert result.clean is False
    assert not marker.exists(), "git.status must not execute the fsmonitor hook"


def test_git_status_rejects_parent_repository(git_repo):
    # Workspace-like directory that lives INSIDE a parent Git repository but
    # is not itself a repository (the exact scenario that leaked ../ paths).
    workspace_dir = git_repo / "workspace"
    workspace_dir.mkdir()
    _write(git_repo, "a.txt", "hello")

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_status(root=workspace_dir)

    event = audit.read_recent(limit=10)[-1]
    assert event["tool"] == "git.status"
    assert event["action"] == "failure"
    assert event["error_type"] == "WorkspaceBoundaryViolation"


def test_git_diff_rejects_parent_repository(git_repo):
    workspace_dir = git_repo / "workspace"
    workspace_dir.mkdir()

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_diff(root=workspace_dir)

    # Even with a path filter, the boundary violation wins: no parent-repo
    # diff data may be returned.
    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_diff(path="a.txt", root=workspace_dir)


def test_git_tools_work_when_workspace_is_a_repository(git_repo):
    # The workspace itself being the repository must keep working, and the
    # returned paths must be workspace-relative (never ../-prefixed).
    _write(git_repo, "a.txt", "hello\n")
    _git(git_repo, "add", "a.txt")
    _write(git_repo, "a.txt", "hello\nworld\n")

    status = git_status(root=git_repo)
    assert status.branch is not None
    assert any(entry.path == "a.txt" for entry in status.entries)
    assert not any(entry.path.startswith("..") for entry in status.entries)

    diff = git_diff(root=git_repo)
    assert diff.additions == 1
    assert "+world" in diff.raw


def test_git_tools_work_in_nested_repo_inside_workspace(temp_dir):
    # A repository nested entirely inside the workspace must remain valid
    # when the tool is addressed at that repository's location.
    workspace_dir = temp_dir
    project = workspace_dir / "project"
    project.mkdir()
    subprocess.run(
        ["git", "init", "-q", str(project)],
        capture_output=True,
        text=True,
        check=True,
    )
    _write(project, "a.txt", "hello")
    _git(project, "add", "a.txt")

    status = git_status(root=project)
    assert status.branch is not None
    assert any(entry.path == "a.txt" for entry in status.entries)
    assert not any(entry.path.startswith("..") for entry in status.entries)

    diff = git_diff(staged=True, root=project)
    assert diff.additions == 1

    # The workspace directory itself has no repository of its own, so
    # discovery from it would escape upward to a parent repository: it must
    # be rejected rather than exposing parent-repository data.
    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_status(root=workspace_dir)


def test_git_status_creates_audit_record(git_repo):
    _write(git_repo, "a.txt", "hello")

    result = git_status(root=git_repo)
    assert result.clean is False

    event = audit.read_recent(limit=10)[-1]
    assert event["tool"] == "git.status"
    assert event["action"] == "read"
    assert event["success"] is True
    assert event["executed"] is True


def test_git_diff_creates_audit_record(git_repo):
    _write(git_repo, "a.txt", "one\n")
    _git(git_repo, "add", "a.txt")

    result = git_diff(staged=True, root=git_repo)
    assert result.additions == 1

    event = audit.read_recent(limit=10)[-1]
    assert event["tool"] == "git.diff"
    assert event["action"] == "read"
    assert event["arguments"]["staged"] is True
