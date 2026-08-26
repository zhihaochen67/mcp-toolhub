"""Security and integration coverage for process-level workspace selection."""

from __future__ import annotations

import difflib
import os
import subprocess
from pathlib import Path

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.paths import (
    RuntimeConfigurationError,
    StateConfigurationError,
    WorkspaceConfigurationError,
    _reset_runtime_configuration_for_tests,
    get_state_root,
    get_workspace_root,
    initialize_runtime_configuration,
)
from mcp_toolhub.tools.filesystem import (
    apply_patch,
    apply_patch_approved,
    read_file,
    write_file,
    write_file_approved,
)
from mcp_toolhub.tools.git import git_diff, git_status
from mcp_toolhub.tools.shell import run_shell


def _configure(monkeypatch, root: Path | str) -> Path:
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(root))
    _reset_runtime_configuration_for_tests()
    return get_workspace_root()


def _patch(name: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )


def test_workspace_is_required(monkeypatch):
    monkeypatch.delenv("TOOLHUB_WORKSPACE_ROOT", raising=False)
    _reset_runtime_configuration_for_tests()

    with pytest.raises(WorkspaceConfigurationError, match="is required"):
        get_workspace_root()


def test_relative_workspace_is_rejected(temp_dir, monkeypatch):
    monkeypatch.chdir(temp_dir.parent)
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", temp_dir.name)
    _reset_runtime_configuration_for_tests()

    with pytest.raises(WorkspaceConfigurationError, match="must be absolute"):
        get_workspace_root()


def test_external_workspace_is_canonical_and_frozen(temp_dir, monkeypatch):
    configured = _configure(monkeypatch, temp_dir)
    configured_state = get_state_root()

    assert configured == temp_dir.resolve()
    assert configured.is_absolute()
    assert initialize_runtime_configuration().workspace_root == configured

    other = temp_dir / "other-workspace"
    other.mkdir()
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(other))
    monkeypatch.setenv(
        "TOOLHUB_STATE_ROOT", str((temp_dir.parent / "ignored-state").resolve())
    )

    # Startup configuration is immutable even if trusted process state is
    # changed later; all tools continue to share one boundary.
    assert get_workspace_root() == temp_dir.resolve()
    assert get_state_root() == configured_state


def test_default_state_root_uses_platform_directory(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "platform-state"
    workspace.mkdir()
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace.resolve()))
    monkeypatch.delenv("TOOLHUB_STATE_ROOT", raising=False)
    monkeypatch.setattr(
        "mcp_toolhub.security.paths.user_state_path",
        lambda *_args, **_kwargs: state_root,
    )
    _reset_runtime_configuration_for_tests()

    configuration = initialize_runtime_configuration()

    assert configuration.state_root == state_root.resolve()
    assert state_root.is_dir()


@pytest.mark.parametrize("value", ["", "relative/state"])
def test_invalid_state_root_value_is_rejected(temp_dir, monkeypatch, value):
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", value)
    _reset_runtime_configuration_for_tests()

    with pytest.raises(StateConfigurationError):
        initialize_runtime_configuration()


def test_filesystem_read_uses_configured_external_workspace(temp_dir, monkeypatch):
    (temp_dir / "readme.txt").write_text("external\n", encoding="utf-8")
    _configure(monkeypatch, temp_dir)

    result = read_file("readme.txt")

    assert result.path == "readme.txt"
    assert result.content == "external\n"


def test_write_and_patch_approvals_are_bound_to_external_workspace(
    temp_dir, monkeypatch
):
    root = _configure(monkeypatch, temp_dir)

    write = write_file("new.txt", "old\n")
    stored_write = approval.get_request(write.request_id)
    assert stored_write.payload["workspace_root"] == str(root)
    approval.approve_request(write.request_id)
    written = write_file_approved(write.request_id)

    assert written.executed is True
    assert (root / "new.txt").read_text(encoding="utf-8") == "old\n"

    patch = apply_patch("new.txt", _patch("new.txt", "old\n", "new\n"))
    stored_patch = approval.get_request(patch.request_id)
    assert stored_patch.payload["workspace_root"] == str(root)
    approval.approve_request(patch.request_id)
    patched = apply_patch_approved(patch.request_id)

    assert patched.executed is True
    assert (root / "new.txt").read_text(encoding="utf-8") == "new\n"


def test_shell_cwd_uses_configured_external_workspace(temp_dir, monkeypatch):
    _configure(monkeypatch, temp_dir)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, stdout="Python 3.13\n", stderr=""
        )

    monkeypatch.setattr("mcp_toolhub.tools.shell.subprocess.run", fake_run)

    result = run_shell("python", ["--version"])

    assert result.executed is True
    assert result.cwd == "."
    assert calls == []


def test_git_status_and_diff_use_configured_external_workspace(
    git_repo, run_git, monkeypatch
):
    (git_repo / "tracked.txt").write_text("one\n", encoding="utf-8")
    run_git("add", "tracked.txt", cwd=git_repo)
    (git_repo / "tracked.txt").write_text("one\ntwo\n", encoding="utf-8")
    _configure(monkeypatch, git_repo)

    status = git_status()
    diff = git_diff()

    assert any(entry.path == "tracked.txt" for entry in status.entries)
    assert "+two" in diff.raw


def test_traversal_outside_external_workspace_is_rejected(temp_dir, monkeypatch):
    outside = temp_dir.parent / "outside-workspace.txt"
    outside.write_text("secret", encoding="utf-8")
    _configure(monkeypatch, temp_dir)

    with pytest.raises(ValueError, match="escapes workspace"):
        read_file("../outside-workspace.txt")


def test_parent_git_repository_outside_external_workspace_is_rejected(
    git_repo, monkeypatch
):
    workspace = git_repo / "external-workspace"
    workspace.mkdir()
    _configure(monkeypatch, workspace)

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_status()

    with pytest.raises(ValueError, match="escapes ToolHub workspace"):
        git_diff()


def test_external_workspace_mutation_symlink_protection_still_applies(
    temp_dir, monkeypatch
):
    _configure(monkeypatch, temp_dir)
    original = Path.is_symlink

    def fake_is_symlink(path):
        return path.name == "link" or original(path)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(ValueError, match="Symlinks are not allowed"):
        write_file("link/file.txt", "blocked")


def test_toolhub_state_stays_outside_workspace_and_is_not_agent_readable(
    temp_dir, isolated_approval_store, monkeypatch
):
    root = _configure(monkeypatch, temp_dir)
    state_root = get_state_root()
    audit_path = state_root / "audit.jsonl"

    assert isolated_approval_store == state_root / "approvals.json"
    assert audit_path == state_root / "audit.jsonl"
    assert not state_root.is_relative_to(root)
    assert not isolated_approval_store.is_relative_to(root)
    assert not audit_path.is_relative_to(root)

    request = write_file("ordinary.txt", "content")
    assert request.executed is False
    audit.record_event(tool="test", action="state-boundary")
    assert isolated_approval_store.exists()
    assert audit_path.exists()
    assert not (root / ".toolhub").exists()

    for trusted_path in (isolated_approval_store, audit_path):
        relative_escape = os.path.relpath(trusted_path, root)
        with pytest.raises(ValueError, match="escapes workspace"):
            read_file(relative_escape)
        with pytest.raises(ValueError, match="escapes workspace"):
            read_file(str(trusted_path.resolve()))


def test_invalid_workspace_configuration_fails_clearly(temp_dir, monkeypatch):
    missing = temp_dir / "does-not-exist"
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(missing))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(
        WorkspaceConfigurationError,
        match="Invalid TOOLHUB_WORKSPACE_ROOT.*does not exist",
    ):
        initialize_runtime_configuration()

    not_directory = temp_dir / "file.txt"
    not_directory.write_text("x", encoding="utf-8")
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(not_directory))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(
        WorkspaceConfigurationError,
        match="Invalid TOOLHUB_WORKSPACE_ROOT.*not a directory",
    ):
        get_workspace_root()


def test_workspace_cannot_contain_trusted_toolhub_state(temp_dir, monkeypatch):
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str((temp_dir / "state").resolve()))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(
        RuntimeConfigurationError,
        match="TOOLHUB_STATE_ROOT must be outside",
    ):
        initialize_runtime_configuration()


def test_external_git_repository_integration_smoke_flow(git_repo, run_git, monkeypatch):
    root = _configure(monkeypatch, git_repo)
    (root / "flow.txt").write_text("before\n", encoding="utf-8")
    run_git("add", "flow.txt", cwd=root)
    (root / "flow.txt").write_text("before\nafter\n", encoding="utf-8")

    read = read_file("flow.txt")

    shell_calls = []

    def fake_run(command, **kwargs):
        shell_calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    # The shell and git modules share Python's subprocess module object, so
    # scope the shell mock to this one execution before exercising real git.
    with monkeypatch.context() as shell_patch:
        shell_patch.setattr("mcp_toolhub.tools.shell.subprocess.run", fake_run)
        shell = run_shell("python", ["--version"])

    status = git_status()
    diff = git_diff(path="flow.txt")

    assert get_workspace_root() == root
    assert read.content == "before\nafter\n"
    assert shell.executed is True
    assert shell.cwd == "."
    assert shell_calls == []
    assert any(entry.path == "flow.txt" for entry in status.entries)
    assert "+after" in diff.raw
