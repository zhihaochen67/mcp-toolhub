"""POSIX coverage for private trusted-state permissions."""

from __future__ import annotations

import errno
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security import paths as security_paths
from mcp_toolhub.security.paths import StateConfigurationError
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.security.state_permissions import open_trusted_file

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX permission bits are not enforced on Windows",
)


@contextmanager
def _temporary_umask(mask: int):
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _initialize_fresh_state(temp_dir: Path, *, umask: int) -> tuple[Path, Path]:
    workspace = temp_dir / f"workspace-{umask:o}"
    state_root = temp_dir / f"trusted-state-{umask:o}"
    workspace.mkdir()
    os.chmod(workspace, 0o755)

    with _temporary_umask(umask):
        loaded = security_paths._load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert loaded == state_root.resolve()
    return workspace, state_root


def _create_approval(store_path: Path):
    return approval.create_request(
        program="python",
        args=["--version"],
        risk=RiskLevel.MEDIUM,
        risk_reason="permission test",
        store_path=store_path,
    )


def _initialize_default_state(
    temp_dir: Path,
    monkeypatch,
    *,
    umask: int,
) -> tuple[Path, tuple[Path, Path], Path, Path, Path]:
    workspace = temp_dir / f"default-workspace-{umask:o}"
    existing_ancestor = temp_dir / f"home-{umask:o}"
    local_directory = existing_ancestor / ".local"
    external_parent = local_directory / "state"
    toolhub_root = external_parent / "mcp-toolhub"
    workspaces_root = toolhub_root / "workspaces"
    workspace.mkdir()
    existing_ancestor.mkdir()
    os.chmod(existing_ancestor, 0o755)
    monkeypatch.setattr(
        security_paths,
        "user_state_path",
        lambda *_args, **_kwargs: toolhub_root,
    )

    with _temporary_umask(umask):
        state_root = security_paths._load_state_root({}, workspace.resolve())

    assert _mode(existing_ancestor) == 0o755
    return (
        existing_ancestor,
        (local_directory, external_parent),
        toolhub_root,
        workspaces_root,
        state_root,
    )


def _assert_default_hierarchy_is_private(
    toolhub_root: Path,
    workspaces_root: Path,
    state_root: Path,
) -> None:
    assert _mode(toolhub_root) == 0o700
    assert _mode(workspaces_root) == 0o700
    assert _mode(state_root) == 0o700
    assert _mode(state_root / "workspace-binding.json") == 0o600
    assert _mode(state_root / "workspace-binding.json.lock") == 0o600


def test_default_hierarchy_is_private_under_restrictive_umask(
    temp_dir,
    monkeypatch,
):
    (
        _external,
        created_external,
        toolhub_root,
        workspaces_root,
        state_root,
    ) = _initialize_default_state(temp_dir, monkeypatch, umask=0o777)

    assert [_mode(path) for path in created_external] == [0o700, 0o700]
    _assert_default_hierarchy_is_private(toolhub_root, workspaces_root, state_root)


def test_default_hierarchy_is_private_under_permissive_umask(
    temp_dir,
    monkeypatch,
):
    (
        _external,
        created_external,
        toolhub_root,
        workspaces_root,
        state_root,
    ) = _initialize_default_state(temp_dir, monkeypatch, umask=0)

    assert [_mode(path) for path in created_external] == [0o700, 0o700]
    _assert_default_hierarchy_is_private(toolhub_root, workspaces_root, state_root)


def test_existing_broad_default_hierarchy_is_tightened(temp_dir, monkeypatch):
    workspace = temp_dir / "broad-workspace"
    external_parent = temp_dir / "broad-platform-user-state"
    toolhub_root = external_parent / "mcp-toolhub"
    workspaces_root = toolhub_root / "workspaces"
    workspace.mkdir()
    external_parent.mkdir()
    toolhub_root.mkdir()
    workspaces_root.mkdir()
    os.chmod(external_parent, 0o755)
    os.chmod(toolhub_root, 0o777)
    os.chmod(workspaces_root, 0o777)
    monkeypatch.setattr(
        security_paths,
        "user_state_path",
        lambda *_args, **_kwargs: toolhub_root,
    )

    state_root = security_paths._load_state_root({}, workspace.resolve())

    assert _mode(external_parent) == 0o755
    _assert_default_hierarchy_is_private(toolhub_root, workspaces_root, state_root)


def test_default_hierarchy_symlink_fails_without_chmodding_target(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "symlink-workspace"
    external_parent = temp_dir / "symlink-platform-user-state"
    target = temp_dir / "symlink-target"
    toolhub_root = external_parent / "mcp-toolhub"
    workspace.mkdir()
    external_parent.mkdir()
    target.mkdir()
    sentinel = target / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    os.chmod(external_parent, 0o755)
    os.chmod(target, 0o755)
    os.symlink(target, toolhub_root, target_is_directory=True)
    monkeypatch.setattr(
        security_paths,
        "user_state_path",
        lambda *_args, **_kwargs: toolhub_root,
    )

    with pytest.raises(StateConfigurationError):
        security_paths._load_state_root({}, workspace.resolve())

    assert _mode(external_parent) == 0o755
    assert _mode(target) == 0o755
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_missing_external_component_race_symlink_fails_without_chmodding_target(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "race-workspace"
    existing_ancestor = temp_dir / "race-home"
    raced_component = existing_ancestor / ".local"
    external_parent = raced_component / "state"
    toolhub_root = external_parent / "mcp-toolhub"
    target = temp_dir / "race-target"
    workspace.mkdir()
    existing_ancestor.mkdir()
    target.mkdir()
    sentinel = target / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    os.chmod(target, 0o755)
    monkeypatch.setattr(
        security_paths,
        "user_state_path",
        lambda *_args, **_kwargs: toolhub_root,
    )
    original_mkdir = os.mkdir
    raced = False

    def race_with_symlink(path, mode=0o777):
        nonlocal raced
        if not raced and Path(path) == raced_component:
            raced = True
            os.symlink(target, raced_component, target_is_directory=True)
            raise FileExistsError(errno.EEXIST, "already exists", os.fspath(path))
        return original_mkdir(path, mode)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(security_paths.os, "mkdir", race_with_symlink)
        with pytest.raises(StateConfigurationError):
            security_paths._load_state_root({}, workspace.resolve())

    assert raced is True
    assert _mode(target) == 0o755
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.parametrize("umask", [0, 0o777])
def test_explicit_state_root_creates_private_missing_parents(temp_dir, umask):
    workspace = temp_dir / f"explicit-workspace-{umask:o}"
    existing_ancestor = temp_dir / f"explicit-ancestor-{umask:o}"
    missing_one = existing_ancestor / "missing-one"
    missing_two = missing_one / "missing-two"
    state_root = missing_two / "state"
    workspace.mkdir()
    existing_ancestor.mkdir()
    os.chmod(existing_ancestor, 0o755)

    with _temporary_umask(umask):
        loaded = security_paths._load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert loaded == state_root.resolve()
    assert _mode(existing_ancestor) == 0o755
    assert [_mode(path) for path in (missing_one, missing_two, state_root)] == [
        0o700,
        0o700,
        0o700,
    ]
    assert _mode(state_root / "workspace-binding.json") == 0o600
    assert _mode(state_root / "workspace-binding.json.lock") == 0o600


def test_fresh_state_objects_are_private_under_permissive_umask(temp_dir):
    workspace, state_root = _initialize_fresh_state(temp_dir, umask=0)

    assert _mode(workspace) == 0o755
    assert _mode(state_root) == 0o700
    assert _mode(state_root / "workspace-binding.json") == 0o600
    assert _mode(state_root / "workspace-binding.json.lock") == 0o600


def test_fresh_state_objects_are_usable_under_restrictive_umask(temp_dir):
    _workspace, state_root = _initialize_fresh_state(temp_dir, umask=0o777)

    assert _mode(state_root) == 0o700
    assert _mode(state_root / "workspace-binding.json") == 0o600
    assert _mode(state_root / "workspace-binding.json.lock") == 0o600
    assert (
        json.loads((state_root / "workspace-binding.json").read_text(encoding="utf-8"))[
            "schema_version"
        ]
        == 1
    )


def test_existing_broad_state_root_is_tightened(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "trusted-state"
    workspace.mkdir()
    state_root.mkdir()
    os.chmod(state_root, 0o777)

    security_paths._load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )

    assert _mode(state_root) == 0o700


def test_existing_broad_binding_is_tightened_without_rebinding(temp_dir):
    workspace = temp_dir / "workspace"
    other_workspace = temp_dir / "other-workspace"
    state_root = temp_dir / "trusted-state"
    workspace.mkdir()
    other_workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    original = (
        json.dumps(
            {
                "canonical_workspace": str(workspace.resolve()),
                "schema_version": 1,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    binding_path.write_bytes(original)
    os.chmod(binding_path, 0o666)

    security_paths._load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )

    assert _mode(binding_path) == 0o600
    assert binding_path.read_bytes() == original

    with pytest.raises(StateConfigurationError, match="different ToolHub workspace"):
        security_paths._load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            other_workspace.resolve(),
        )
    assert binding_path.read_bytes() == original


def test_existing_broad_binding_lock_is_tightened_in_place(temp_dir):
    binding_path = temp_dir / "workspace-binding.json"
    lock_path = temp_dir / "workspace-binding.json.lock"
    lock_path.write_bytes(b"")
    os.chmod(lock_path, 0o666)

    with security_paths._binding_lock(binding_path):
        assert _mode(lock_path) == 0o600

    assert _mode(lock_path) == 0o600


def test_binding_temporary_file_is_private_before_publication(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "publication-workspace"
    state_root = temp_dir / "publication-state"
    workspace.mkdir()
    original_link = security_paths.os.link
    observed_modes = []

    def inspect_publication(source, destination):
        observed_modes.append(_mode(Path(source)))
        return original_link(source, destination)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(security_paths.os, "link", inspect_publication)
        security_paths._load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert observed_modes == [0o600]
    assert _mode(state_root / "workspace-binding.json") == 0o600


def test_fresh_approval_store_is_private_under_permissive_umask(temp_dir):
    store_path = temp_dir / "approvals.json"

    with _temporary_umask(0):
        _create_approval(store_path)

    assert _mode(store_path) == 0o600
    assert _mode(store_path.with_name("approvals.json.lock")) == 0o600


def test_approval_store_remains_usable_under_restrictive_umask(temp_dir):
    store_path = temp_dir / "approvals.json"

    with _temporary_umask(0o777):
        created = _create_approval(store_path)
        approved = approval.approve_request(
            created.request_id,
            store_path=store_path,
        )

    assert approved.request_id == created.request_id
    assert approval.get_request(created.request_id, store_path=store_path) is not None
    assert _mode(store_path) == 0o600
    assert _mode(store_path.with_name("approvals.json.lock")) == 0o600


def test_existing_broad_approval_store_and_lock_are_tightened(temp_dir):
    store_path = temp_dir / "approvals.json"
    created = _create_approval(store_path)
    lock_path = store_path.with_name("approvals.json.lock")
    os.chmod(store_path, 0o666)
    os.chmod(lock_path, 0o644)

    approved = approval.approve_request(created.request_id, store_path=store_path)

    assert approved.request_id == created.request_id
    assert _mode(store_path) == 0o600
    assert _mode(lock_path) == 0o600


def test_fresh_audit_log_is_private_under_permissive_umask(temp_dir):
    audit_path = temp_dir / "audit.jsonl"

    with _temporary_umask(0):
        assert audit.record_event(tool="test", action="fresh", audit_path=audit_path)

    assert _mode(audit_path) == 0o600
    assert _mode(audit_path.with_name("audit.jsonl.lock")) == 0o600


def test_audit_log_remains_usable_under_restrictive_umask(temp_dir):
    audit_path = temp_dir / "audit.jsonl"

    with _temporary_umask(0o777):
        assert audit.record_event(
            tool="test",
            action="restrictive",
            audit_path=audit_path,
        )

    assert _mode(audit_path) == 0o600
    assert _mode(audit_path.with_name("audit.jsonl.lock")) == 0o600


def test_existing_broad_audit_log_and_lock_are_tightened(temp_dir):
    audit_path = temp_dir / "audit.jsonl"
    assert audit.record_event(tool="test", action="first", audit_path=audit_path)
    lock_path = audit_path.with_name("audit.jsonl.lock")
    os.chmod(audit_path, 0o666)
    os.chmod(lock_path, 0o644)

    assert audit.record_event(tool="test", action="second", audit_path=audit_path)

    assert _mode(audit_path) == 0o600
    assert _mode(lock_path) == 0o600
    assert [event["action"] for event in audit.read_recent(audit_path=audit_path)] == [
        "first",
        "second",
    ]


def test_audit_compaction_replacement_remains_private(temp_dir):
    audit_path = temp_dir / "audit.jsonl"
    for index in range(3):
        assert audit.record_event(
            tool="test",
            action=f"event-{index}",
            audit_path=audit_path,
        )
    os.chmod(audit_path, 0o666)

    result = audit.compact_audit(2, apply=True, audit_path=audit_path)

    assert result.retained == 2
    assert _mode(audit_path) == 0o600
    assert [event["action"] for event in audit.read_recent(audit_path=audit_path)] == [
        "event-1",
        "event-2",
    ]


def test_state_root_permission_failure_maps_to_configuration_error(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "trusted-state"
    workspace.mkdir()

    def fail_secure_directory(_path):
        raise PermissionError("simulated state-root permission failure")

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "secure_trusted_directory",
            fail_secure_directory,
        )
        with pytest.raises(StateConfigurationError) as captured:
            security_paths._load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

    assert isinstance(captured.value.__cause__, PermissionError)


def test_binding_permission_failure_maps_to_configuration_error(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "trusted-state"
    workspace.mkdir()
    security_paths._load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )
    original_open = security_paths.open_trusted_file

    def fail_binding(path, flags, mode=0o600):
        if Path(path).name == "workspace-binding.json":
            raise PermissionError("simulated binding permission failure")
        return original_open(path, flags, mode)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "open_trusted_file",
            fail_binding,
        )
        with pytest.raises(StateConfigurationError) as captured:
            security_paths._bind_state_namespace(
                state_root.resolve(),
                workspace.resolve(),
            )

    assert isinstance(captured.value.__cause__, PermissionError)


def test_approval_permission_failure_maps_to_store_error(temp_dir, monkeypatch):
    store_path = temp_dir / "approvals.json"
    original_open = approval.open_trusted_file

    def fail_temporary(path, flags, mode=0o600):
        if Path(path).suffix == ".tmp":
            raise PermissionError("simulated approval permission failure")
        return original_open(path, flags, mode)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(approval, "open_trusted_file", fail_temporary)
        with pytest.raises(approval.ApprovalStoreError) as captured:
            _create_approval(store_path)

    assert isinstance(captured.value.__cause__, PermissionError)


def test_audit_permission_failure_remains_non_fatal(temp_dir, monkeypatch):
    audit_path = temp_dir / "audit.jsonl"
    original_open = audit.open_trusted_file

    def fail_audit_log(path, flags, mode=0o600):
        if Path(path) == audit_path:
            raise PermissionError("simulated audit permission failure")
        return original_open(path, flags, mode)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(audit, "open_trusted_file", fail_audit_log)
        assert (
            audit.record_event(
                tool="test",
                action="permission-failure",
                audit_path=audit_path,
            )
            is False
        )


def test_trusted_file_open_does_not_chmod_a_symlink_target(temp_dir):
    target = temp_dir / "target"
    link = temp_dir / "trusted-link"
    target.write_bytes(b"target")
    os.chmod(target, 0o644)
    os.symlink(target, link)

    with pytest.raises(OSError):
        open_trusted_file(link, os.O_RDONLY)

    assert _mode(target) == 0o644
