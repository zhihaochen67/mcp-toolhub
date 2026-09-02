"""Security and integration coverage for process-level workspace selection."""

from __future__ import annotations

import difflib
import errno
import inspect
import json
import multiprocessing
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security import paths as security_paths
from mcp_toolhub.security.paths import (
    RuntimeConfiguration,
    RuntimeConfigurationError,
    StateConfigurationError,
    WorkspaceConfigurationError,
    _load_state_root,
    _reset_runtime_configuration_for_tests,
    _workspace_identifier,
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


def _spawn_bind_worker(
    state_root: str,
    workspace: str,
    ready_queue,
    start_event,
    result_queue,
) -> None:
    """Initialize one binding in a fresh spawn-based child process."""
    ready_queue.put(True)
    if not start_event.wait(15):
        result_queue.put(("unexpected", workspace, "start timeout"))
        return

    try:
        result = security_paths._load_state_root(
            {"TOOLHUB_STATE_ROOT": state_root},
            Path(workspace).resolve(strict=True),
        )
    except StateConfigurationError as exc:
        result_queue.put(("configuration_error", workspace, str(exc)))
    except (OSError, RuntimeError, ValueError) as exc:  # pragma: no cover
        result_queue.put(("unexpected", workspace, repr(exc)))
    else:
        result_queue.put(("success", workspace, str(result)))


def _run_spawn_binding_race(state_root: Path, workspaces: list[Path]):
    context = multiprocessing.get_context("spawn")
    ready_queue = context.Queue()
    result_queue = context.Queue()
    start_event = context.Event()
    processes = [
        context.Process(
            target=_spawn_bind_worker,
            args=(
                str(state_root.resolve()),
                str(workspace.resolve()),
                ready_queue,
                start_event,
                result_queue,
            ),
        )
        for workspace in workspaces
    ]

    try:
        for process in processes:
            process.start()
        for _process in processes:
            assert ready_queue.get(timeout=20) is True

        start_event.set()
        results = [result_queue.get(timeout=20) for _process in processes]
        for process in processes:
            process.join(20)

        assert [process.exitcode for process in processes] == [0] * len(processes)
        return results
    finally:
        start_event.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(10)
        ready_queue.close()
        result_queue.close()


def _spawn_hold_binding_lock(
    binding_path: str,
    acquired_event,
    release_event,
) -> None:
    with security_paths._binding_lock(
        Path(binding_path),
        timeout_seconds=10,
    ):
        acquired_event.set()
        if not release_event.wait(15):
            raise TimeoutError("test holder release timeout")


def _spawn_binding_lock_contender(
    binding_path: str,
    attempting_event,
    acquired_event,
) -> None:
    attempting_event.set()
    with security_paths._binding_lock(
        Path(binding_path),
        timeout_seconds=10,
    ):
        acquired_event.set()


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

    workspace_id = _workspace_identifier(workspace.resolve())
    expected = state_root / "workspaces" / workspace_id
    assert configuration.state_root == expected.resolve()
    assert workspace_id.isalnum()
    assert len(workspace_id) == 64
    assert workspace.name not in workspace_id

    binding = json.loads(
        (expected / "workspace-binding.json").read_text(encoding="utf-8")
    )
    assert binding == {
        "schema_version": 1,
        "canonical_workspace": str(workspace.resolve()),
    }


def test_default_state_namespaces_are_deterministic_and_workspace_isolated(
    temp_dir, monkeypatch
):
    state_base = temp_dir / "platform-state"
    workspace_a = temp_dir / "workspace-a"
    workspace_b = temp_dir / "workspace-b"
    workspace_a.mkdir()
    workspace_b.mkdir()
    monkeypatch.setattr(
        "mcp_toolhub.security.paths.user_state_path",
        lambda *_args, **_kwargs: state_base,
    )
    monkeypatch.delenv("TOOLHUB_STATE_ROOT", raising=False)

    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace_a.resolve()))
    _reset_runtime_configuration_for_tests()
    state_a = get_state_root()

    _reset_runtime_configuration_for_tests()
    assert get_state_root() == state_a

    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace_b.resolve()))
    _reset_runtime_configuration_for_tests()
    state_b = get_state_root()

    assert state_a != state_b
    assert state_a.parent == state_b.parent == (state_base / "workspaces").resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows path case semantics")
def test_default_workspace_identifier_is_case_insensitive_on_windows(temp_dir):
    canonical = temp_dir.resolve()
    case_variant = Path(str(canonical).swapcase())

    assert _workspace_identifier(case_variant) == _workspace_identifier(canonical)


def test_explicit_state_root_binds_once_to_one_workspace(temp_dir, monkeypatch):
    workspace_a = temp_dir / "workspace-a"
    workspace_b = temp_dir / "workspace-b"
    state_root = temp_dir / "explicit-state"
    workspace_a.mkdir()
    workspace_b.mkdir()
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(state_root.resolve()))

    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace_a.resolve()))
    _reset_runtime_configuration_for_tests()
    assert get_state_root() == state_root.resolve()

    _reset_runtime_configuration_for_tests()
    assert get_state_root() == state_root.resolve()

    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace_b.resolve()))
    _reset_runtime_configuration_for_tests()
    with pytest.raises(StateConfigurationError, match="different ToolHub workspace"):
        get_state_root()


def test_explicit_state_root_creates_missing_parents(temp_dir):
    workspace = temp_dir / "workspace"
    existing_parent = temp_dir / "existing-parent"
    missing_one = existing_parent / "missing-one"
    missing_two = missing_one / "missing-two"
    state_root = missing_two / "explicit-state"
    workspace.mkdir()
    existing_parent.mkdir()

    loaded = _load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )

    assert loaded == state_root.resolve()
    assert missing_one.is_dir()
    assert missing_two.is_dir()
    assert (state_root / "workspace-binding.json").is_file()
    assert (state_root / "workspace-binding.json.lock").is_file()


def test_empty_existing_state_root_initializes_and_remains_stable(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()

    loaded = _load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )
    binding_path = state_root / "workspace-binding.json"
    original = binding_path.read_bytes()

    reloaded = _load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )

    assert loaded == reloaded == state_root.resolve()
    assert binding_path.read_bytes() == original
    assert sorted(path.name for path in state_root.iterdir()) == [
        "workspace-binding.json",
        "workspace-binding.json.lock",
    ]


def test_state_discovery_retries_when_internal_temporary_disappears(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    original_scandir = security_paths.os.scandir
    scans = 0

    class DisappearedTemporary:
        name = ".workspace-binding.json-concurrent.tmp"

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            raise FileNotFoundError(errno.ENOENT, "concurrent temporary removed")

    class TransientSnapshot:
        def __enter__(self):
            return iter([DisappearedTemporary()])

        def __exit__(self, *_args):
            return False

    def transient_scandir(path):
        nonlocal scans
        scans += 1
        if scans == 1:
            return TransientSnapshot()
        return original_scandir(path)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(security_paths.os, "scandir", transient_scandir)
        scoped_monkeypatch.setattr(
            security_paths,
            "_BINDING_READ_INTERVAL_SECONDS",
            0,
        )
        loaded = _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert scans >= 2
    assert loaded == state_root.resolve()
    assert (state_root / "workspace-binding.json").is_file()


def test_state_discovery_does_not_retry_disappeared_persistent_object(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    scans = 0

    class DisappearedApprovalStore:
        name = "approvals.json"

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            raise FileNotFoundError(errno.ENOENT, "persistent state disappeared")

    class InvalidSnapshot:
        def __enter__(self):
            return iter([DisappearedApprovalStore()])

        def __exit__(self, *_args):
            return False

    def invalid_scandir(_path):
        nonlocal scans
        scans += 1
        return InvalidSnapshot()

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(security_paths.os, "scandir", invalid_scandir)
        with pytest.raises(
            StateConfigurationError,
            match="state object cannot be inspected safely",
        ):
            _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

    assert scans == 1
    assert not (state_root / "workspace-binding.json").exists()


def test_known_existing_state_is_preserved_during_initial_binding(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    approval_path = state_root / "approvals.json"
    original = b'{"version":2,"requests":{}}\n'
    approval_path.write_bytes(original)

    loaded = _load_state_root(
        {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
        workspace.resolve(),
    )

    assert loaded == state_root.resolve()
    assert approval_path.read_bytes() == original
    assert sorted(path.name for path in state_root.iterdir()) == [
        "approvals.json",
        "workspace-binding.json",
        "workspace-binding.json.lock",
    ]


def test_known_state_object_with_unsafe_type_is_rejected_without_mutation(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    approval_path = state_root / "approvals.json"
    approval_path.mkdir()

    with pytest.raises(StateConfigurationError, match="not a regular file"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert approval_path.is_dir()
    assert sorted(path.name for path in state_root.iterdir()) == ["approvals.json"]


def test_unexpected_existing_state_object_is_rejected_without_mutation(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    unexpected = state_root / "unrelated.txt"
    unexpected.write_text("unchanged", encoding="utf-8")

    with pytest.raises(StateConfigurationError, match="unexpected state object"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert unexpected.read_text(encoding="utf-8") == "unchanged"
    assert sorted(path.name for path in state_root.iterdir()) == ["unrelated.txt"]


def test_state_root_symlink_is_rejected_without_touching_target(temp_dir):
    workspace = temp_dir / "workspace"
    target = temp_dir / "unrelated-target"
    state_root = temp_dir / "state-link"
    workspace.mkdir()
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    try:
        os.symlink(target, state_root, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(StateConfigurationError, match="must not be a symlink"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.absolute())},
            workspace.resolve(),
        )

    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert sorted(path.name for path in target.iterdir()) == ["sentinel.txt"]


def test_directory_initialization_failure_rolls_back_created_chain(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    existing_parent = temp_dir / "existing-parent"
    missing_parent = existing_parent / "missing-parent"
    state_root = missing_parent / "state"
    workspace.mkdir()
    existing_parent.mkdir()
    original_secure = security_paths.secure_trusted_directory
    calls = 0

    def fail_second_directory(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError(errno.EACCES, "simulated lifecycle failure")
        original_secure(path)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "secure_trusted_directory",
            fail_second_directory,
        )
        with pytest.raises(StateConfigurationError) as captured:
            _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

    assert isinstance(captured.value.__cause__, PermissionError)
    assert not missing_parent.exists()
    assert list(existing_parent.iterdir()) == []


def test_state_binding_failure_rolls_back_empty_created_chain(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    existing_parent = temp_dir / "existing-parent"
    missing_parent = existing_parent / "missing-parent"
    state_root = missing_parent / "state"
    workspace.mkdir()
    existing_parent.mkdir()

    def fail_binding(_state_root, _workspace_root, **_kwargs):
        raise OSError(errno.EIO, "simulated lifecycle binding failure")

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "_bind_state_namespace",
            fail_binding,
        )
        with pytest.raises(
            StateConfigurationError,
            match="state initialization failed",
        ) as captured:
            _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

    assert isinstance(captured.value.__cause__, OSError)
    assert captured.value.__cause__.errno == errno.EIO
    assert not missing_parent.exists()
    assert list(existing_parent.iterdir()) == []


def test_binding_initialization_failure_is_recoverable(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    original_publish = security_paths._publish_binding_manifest
    attempts = 0

    def fail_once(binding_path, serialized):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError(errno.EIO, "simulated lifecycle publication failure")
        original_publish(binding_path, serialized)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "_publish_binding_manifest",
            fail_once,
        )
        with pytest.raises(
            StateConfigurationError,
            match="initialization failed",
        ) as captured:
            _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

        assert isinstance(captured.value.__cause__, OSError)
        assert captured.value.__cause__.errno == errno.EIO
        assert not (state_root / "workspace-binding.json").exists()
        assert not list(state_root.glob(".workspace-binding.json-*.tmp"))

        recovered = _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    assert recovered == state_root.resolve()
    assert attempts == 2
    assert (state_root / "workspace-binding.json").is_file()


def test_state_directory_swap_is_rejected_without_modifying_target(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    target = temp_dir / "unrelated-target"
    workspace.mkdir()
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    probe = temp_dir / "symlink-probe"
    try:
        os.symlink(target, probe, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    probe.unlink()
    original_secure = security_paths.secure_trusted_directory

    def swap_state_directory(path):
        original_secure(path)
        if Path(path) == state_root:
            state_root.rmdir()
            os.symlink(target, state_root, target_is_directory=True)

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(
            security_paths,
            "secure_trusted_directory",
            swap_state_directory,
        )
        with pytest.raises(StateConfigurationError) as captured:
            _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )

    assert isinstance(captured.value.__cause__, OSError)
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert sorted(path.name for path in target.iterdir()) == ["sentinel.txt"]


def test_state_lifecycle_path_does_not_change_process_umask():
    lifecycle_source = "\n".join(
        inspect.getsource(function)
        for function in (
            security_paths._ensure_directory_component,
            security_paths._ensure_directory_chain,
            security_paths._inspect_state_directory,
            security_paths._inspect_existing_state_candidate,
            security_paths._validate_planned_state_location,
            security_paths._load_state_root,
            security_paths._validate_supplied_configuration,
        )
    )

    assert "os.umask" not in lifecycle_source


def test_rejected_configuration_after_freeze_does_not_touch_other_state(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    other_workspace = temp_dir / "other-workspace"
    other_state = temp_dir / "other-state"
    workspace.mkdir()
    state_root.mkdir()
    other_workspace.mkdir()
    other_state.mkdir()
    unexpected = other_state / "unrelated.txt"
    unexpected.write_text("unchanged", encoding="utf-8")
    configured = RuntimeConfiguration(
        state_root=state_root.resolve(),
        workspace_root=workspace.resolve(),
    )
    rejected = RuntimeConfiguration(
        state_root=other_state.resolve(),
        workspace_root=other_workspace.resolve(),
    )
    _reset_runtime_configuration_for_tests()

    assert initialize_runtime_configuration(configured) == configured
    with pytest.raises(RuntimeConfigurationError, match="already frozen"):
        initialize_runtime_configuration(rejected)

    assert unexpected.read_text(encoding="utf-8") == "unchanged"
    assert sorted(path.name for path in other_state.iterdir()) == ["unrelated.txt"]


@pytest.mark.parametrize(
    "binding",
    [
        "not-json",
        json.dumps({"schema_version": 1}),
        json.dumps({"canonical_workspace": "C:/missing"}),
        json.dumps({"schema_version": 99, "canonical_workspace": "C:/missing"}),
    ],
)
def test_explicit_state_root_malformed_binding_fails_closed(
    temp_dir, monkeypatch, binding
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "explicit-state"
    workspace.mkdir()
    state_root.mkdir()
    (state_root / "workspace-binding.json").write_text(binding, encoding="utf-8")
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(state_root.resolve()))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(StateConfigurationError, match="workspace binding"):
        get_state_root()


def test_binding_read_accepts_exact_byte_boundary_and_rejects_one_less(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    serialized = (
        json.dumps(
            {
                "canonical_workspace": str(workspace.resolve()),
                "schema_version": 1,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    binding_path.write_bytes(serialized)

    monkeypatch.setattr(
        security_paths,
        "_BINDING_MAX_READ_BYTES",
        len(serialized),
    )
    security_paths._read_binding_manifest(binding_path, workspace.resolve())

    monkeypatch.setattr(
        security_paths,
        "_BINDING_MAX_READ_BYTES",
        len(serialized) - 1,
    )
    with pytest.raises(StateConfigurationError, match="exceeds maximum size"):
        security_paths._read_binding_manifest(binding_path, workspace.resolve())


def test_binding_read_rejects_one_byte_over_without_modifying_input(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    limit = 32
    serialized = b"x" * (limit + 1)
    binding_path.write_bytes(serialized)
    monkeypatch.setattr(security_paths, "_BINDING_MAX_READ_BYTES", limit)

    with pytest.raises(StateConfigurationError, match="exceeds maximum size"):
        security_paths._read_binding_manifest(binding_path, workspace.resolve())

    assert binding_path.read_bytes() == serialized


def test_oversized_binding_is_rejected_before_json_parsing(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    limit = 16
    binding_path.write_bytes(b"x" * (limit + 1))
    monkeypatch.setattr(security_paths, "_BINDING_MAX_READ_BYTES", limit)

    def fail_if_called(_serialized):
        raise AssertionError("json.loads must not parse an oversized binding")

    monkeypatch.setattr(security_paths.json, "loads", fail_if_called)

    with pytest.raises(StateConfigurationError, match="exceeds maximum size"):
        security_paths._read_binding_manifest(binding_path, workspace.resolve())


def test_binding_read_invalid_utf8_fails_closed(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    binding_path.write_bytes(b"\xff")
    monkeypatch.setattr(security_paths, "_BINDING_READ_TIMEOUT_SECONDS", 0)

    with pytest.raises(
        StateConfigurationError,
        match="manifest is unreadable or malformed",
    ) as captured:
        security_paths._read_binding_manifest(binding_path, workspace.resolve())

    assert isinstance(captured.value.__cause__, UnicodeDecodeError)


def test_binding_read_parser_recursion_fails_closed(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    binding_path.write_bytes(b"{}")
    monkeypatch.setattr(security_paths, "_BINDING_READ_TIMEOUT_SECONDS", 0)

    def recurse(_serialized):
        raise RecursionError("simulated parser recursion")

    monkeypatch.setattr(security_paths.json, "loads", recurse)

    with pytest.raises(
        StateConfigurationError,
        match="manifest is unreadable or malformed",
    ) as captured:
        security_paths._read_binding_manifest(binding_path, workspace.resolve())

    assert isinstance(captured.value.__cause__, RecursionError)


def test_binding_read_parser_memory_error_is_not_swallowed(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    binding_path.write_bytes(b"{}")

    def exhaust_memory(_serialized):
        raise MemoryError("simulated parser exhaustion")

    monkeypatch.setattr(security_paths.json, "loads", exhaust_memory)

    with pytest.raises(MemoryError, match="simulated parser exhaustion"):
        security_paths._read_binding_manifest(binding_path, workspace.resolve())


def test_concurrent_explicit_first_bind_allows_only_one_workspace(temp_dir):
    workspace_a = temp_dir / "workspace-a"
    workspace_b = temp_dir / "workspace-b"
    state_root = temp_dir / "explicit-state"
    workspace_a.mkdir()
    workspace_b.mkdir()
    barrier = threading.Barrier(2)

    def bind(workspace):
        barrier.wait()
        try:
            return _load_state_root(
                {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
                workspace.resolve(),
            )
        except StateConfigurationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(bind, (workspace_a, workspace_b)))

    assert sum(result is not None for result in results) == 1
    binding = json.loads(
        (state_root / "workspace-binding.json").read_text(encoding="utf-8")
    )
    assert binding["canonical_workspace"] in {
        str(workspace_a.resolve()),
        str(workspace_b.resolve()),
    }


def test_concurrent_same_workspace_first_bind_both_succeed(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "explicit-state"
    workspace.mkdir()
    barrier = threading.Barrier(2)

    def bind():
        barrier.wait()
        return _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: bind(), range(2)))

    assert results == [state_root.resolve(), state_root.resolve()]


def test_spawned_same_workspace_initializers_all_succeed(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "spawn-state"
    workspace.mkdir()

    results = _run_spawn_binding_race(state_root, [workspace] * 6)

    assert [result[0] for result in results] == ["success"] * 6
    binding_paths = list(state_root.glob("workspace-binding.json"))
    assert binding_paths == [state_root / "workspace-binding.json"]
    payload = json.loads(binding_paths[0].read_text(encoding="utf-8"))
    assert payload == {
        "canonical_workspace": str(workspace.resolve()),
        "schema_version": 1,
    }
    assert (state_root / "workspace-binding.json.lock").is_file()
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_spawned_different_workspace_initializers_cannot_rebind(temp_dir):
    workspace_a = temp_dir / "workspace-a"
    workspace_b = temp_dir / "workspace-b"
    state_root = temp_dir / "spawn-state"
    workspace_a.mkdir()
    workspace_b.mkdir()

    results = _run_spawn_binding_race(state_root, [workspace_a, workspace_b])

    assert sorted(result[0] for result in results) == [
        "configuration_error",
        "success",
    ]
    winning_workspace = next(result[1] for result in results if result[0] == "success")
    losing_workspace = next(
        result[1] for result in results if result[0] == "configuration_error"
    )
    payload = json.loads(
        (state_root / "workspace-binding.json").read_text(encoding="utf-8")
    )
    assert payload == {
        "canonical_workspace": winning_workspace,
        "schema_version": 1,
    }

    with pytest.raises(StateConfigurationError, match="different ToolHub workspace"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            Path(losing_workspace),
        )
    assert (
        json.loads((state_root / "workspace-binding.json").read_text(encoding="utf-8"))
        == payload
    )


def test_binding_lock_serializes_processes_and_remains_reusable(temp_dir):
    state_root = temp_dir / "state"
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    lock_path = state_root / "workspace-binding.json.lock"
    context = multiprocessing.get_context("spawn")
    holder_acquired = context.Event()
    holder_release = context.Event()
    contender_attempting = context.Event()
    contender_acquired = context.Event()
    holder = context.Process(
        target=_spawn_hold_binding_lock,
        args=(str(binding_path), holder_acquired, holder_release),
    )
    contender = context.Process(
        target=_spawn_binding_lock_contender,
        args=(str(binding_path), contender_attempting, contender_acquired),
    )

    try:
        holder.start()
        assert holder_acquired.wait(10)
        contender.start()
        assert contender_attempting.wait(10)
        assert not contender_acquired.wait(0.3)

        holder_release.set()
        assert contender_acquired.wait(10)
        holder.join(10)
        contender.join(10)
        assert holder.exitcode == 0
        assert contender.exitcode == 0
    finally:
        holder_release.set()
        for process in (holder, contender):
            if process.is_alive():
                process.terminate()
            process.join(10)

    assert lock_path.is_file()
    with security_paths._binding_lock(binding_path, timeout_seconds=1):
        assert lock_path.is_file()
    assert lock_path.is_file()


def test_binding_lock_timeout_maps_to_path_free_configuration_error(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    context = multiprocessing.get_context("spawn")
    holder_acquired = context.Event()
    holder_release = context.Event()
    holder = context.Process(
        target=_spawn_hold_binding_lock,
        args=(str(binding_path), holder_acquired, holder_release),
    )

    try:
        holder.start()
        assert holder_acquired.wait(10)
        monkeypatch.setattr(
            security_paths,
            "_BINDING_LOCK_TIMEOUT_SECONDS",
            0.1,
        )

        with pytest.raises(
            StateConfigurationError,
            match="initialization lock acquisition timed out",
        ) as captured:
            security_paths._bind_state_namespace(
                state_root.resolve(),
                workspace.resolve(),
            )

        assert isinstance(captured.value.__cause__, TimeoutError)
        assert str(state_root.resolve()) not in str(captured.value)
        assert str(workspace.resolve()) not in str(captured.value)
    finally:
        holder_release.set()
        if holder.is_alive():
            holder.join(10)
        if holder.is_alive():
            holder.terminate()
        holder.join(10)

    assert holder.exitcode == 0


def test_binding_lock_is_released_when_holding_process_terminates(temp_dir):
    state_root = temp_dir / "state"
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    lock_path = state_root / "workspace-binding.json.lock"
    context = multiprocessing.get_context("spawn")
    holder_acquired = context.Event()
    never_release = context.Event()
    holder = context.Process(
        target=_spawn_hold_binding_lock,
        args=(str(binding_path), holder_acquired, never_release),
    )

    holder.start()
    try:
        assert holder_acquired.wait(10)
        holder.terminate()
        holder.join(10)
        assert not holder.is_alive()

        assert lock_path.is_file()
        with security_paths._binding_lock(binding_path, timeout_seconds=1):
            assert lock_path.is_file()
    finally:
        if holder.is_alive():
            holder.terminate()
        holder.join(10)

    assert lock_path.is_file()


def test_binding_lock_open_permission_error_is_not_retried(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    calls = []

    def deny_open(path, flags, mode=0o777):
        calls.append((Path(path), flags, mode))
        raise PermissionError(errno.EACCES, "denied")

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(security_paths.os, "open", deny_open)

        with pytest.raises(
            StateConfigurationError, match="initialization failed"
        ) as captured:
            security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, PermissionError)
    assert [call[0] for call in calls] == [state_root / "workspace-binding.json.lock"]


def test_binding_lock_non_contention_error_is_not_retried(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    calls = 0

    def fail_lock(_descriptor):
        nonlocal calls
        calls += 1
        raise OSError(errno.EIO, "simulated lock failure")

    monkeypatch.setattr(security_paths, "_acquire_binding_os_lock", fail_lock)

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert calls == 1
    assert isinstance(captured.value.__cause__, OSError)
    assert captured.value.__cause__.errno == errno.EIO
    assert (state_root / "workspace-binding.json.lock").is_file()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
def test_binding_temporary_file_is_private_before_publication(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    original_link = security_paths.os.link
    observed_modes = []

    def inspect_publication(source, destination):
        observed_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        return original_link(source, destination)

    monkeypatch.setattr(security_paths.os, "link", inspect_publication)

    security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert observed_modes == [0o600]
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
def test_published_binding_manifest_is_private(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()

    security_paths._bind_state_namespace(state_root, workspace.resolve())

    binding_path = state_root / "workspace-binding.json"
    assert stat.S_IMODE(binding_path.stat().st_mode) == 0o600


def test_binding_temporary_file_collision_is_not_removed(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    monkeypatch.setattr(security_paths.secrets, "token_hex", lambda _size: "fixed")
    temporary_path = state_root / ".workspace-binding.json-fixed.tmp"
    original = b"unowned temporary file\n"
    temporary_path.write_bytes(original)

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, FileExistsError)
    assert temporary_path.read_bytes() == original
    assert not (state_root / "workspace-binding.json").exists()


def test_binding_permission_normalization_failure_cleans_owned_temporary_file(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()

    def fail_permissions(_descriptor):
        raise PermissionError(errno.EACCES, "simulated permission failure")

    monkeypatch.setattr(
        security_paths,
        "secure_trusted_file_descriptor",
        fail_permissions,
    )

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, PermissionError)
    assert not (state_root / "workspace-binding.json").exists()
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_binding_short_writes_are_completed_before_publication(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    original_write = security_paths.os.write
    write_sizes = []

    def short_write(descriptor, data):
        chunk = data[:7]
        write_sizes.append(len(chunk))
        return original_write(descriptor, chunk)

    monkeypatch.setattr(security_paths.os, "write", short_write)

    security_paths._bind_state_namespace(state_root, workspace.resolve())

    binding_path = state_root / "workspace-binding.json"
    assert len(write_sizes) > 1
    assert json.loads(binding_path.read_text(encoding="utf-8")) == {
        "canonical_workspace": str(workspace.resolve()),
        "schema_version": 1,
    }


def test_binding_write_failure_preserves_binding_that_appears(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    winner = temp_dir / "winner"
    state_root = temp_dir / "state"
    workspace.mkdir()
    winner.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    winner_payload = (
        json.dumps(
            {
                "canonical_workspace": str(winner.resolve()),
                "schema_version": 1,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    def fail_write(_descriptor, _serialized):
        binding_path.write_bytes(winner_payload)
        raise OSError(errno.EIO, "simulated write failure")

    monkeypatch.setattr(security_paths.os, "write", fail_write)

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, OSError)
    assert captured.value.__cause__.errno == errno.EIO
    assert binding_path.read_bytes() == winner_payload
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_binding_fsync_failure_prevents_publication(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()

    def fail_fsync(_descriptor):
        raise OSError(errno.EIO, "simulated fsync failure")

    monkeypatch.setattr(security_paths.os, "fsync", fail_fsync)

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, OSError)
    assert captured.value.__cause__.errno == errno.EIO
    assert not (state_root / "workspace-binding.json").exists()
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_binding_publication_never_overwrites_manifest_that_appears(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    winner = temp_dir / "winner"
    state_root = temp_dir / "state"
    workspace.mkdir()
    winner.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    winner_payload = {
        "canonical_workspace": str(winner.resolve()),
        "schema_version": 1,
    }

    def concurrent_publish(_source, destination):
        Path(destination).write_text(json.dumps(winner_payload), encoding="utf-8")
        raise FileExistsError(errno.EEXIST, "binding appeared")

    monkeypatch.setattr(security_paths.os, "link", concurrent_publish)

    with pytest.raises(StateConfigurationError, match="different ToolHub workspace"):
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert json.loads(binding_path.read_text(encoding="utf-8")) == winner_payload
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_binding_publication_rejects_final_symlink_race_without_touching_target(
    temp_dir,
    monkeypatch,
):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    binding_path = state_root / "workspace-binding.json"
    target = state_root / "unrelated-target.json"
    original = b"unrelated content\n"
    target.write_bytes(original)
    probe = state_root / "symlink-probe"
    try:
        os.symlink(target, probe)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    probe.unlink()

    def concurrent_symlink(_source, destination):
        os.symlink(target, destination)
        raise FileExistsError(errno.EEXIST, "binding symlink appeared")

    monkeypatch.setattr(security_paths.os, "link", concurrent_symlink)

    with pytest.raises(StateConfigurationError, match="must not be a symlink"):
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert binding_path.is_symlink()
    assert target.read_bytes() == original
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_failed_binding_publication_cleans_temporary_file(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()

    def fail_publish(_source, _destination):
        raise OSError(errno.EIO, "simulated publication failure")

    monkeypatch.setattr(security_paths.os, "link", fail_publish)

    with pytest.raises(
        StateConfigurationError, match="initialization failed"
    ) as captured:
        security_paths._bind_state_namespace(state_root, workspace.resolve())

    assert isinstance(captured.value.__cause__, OSError)
    assert captured.value.__cause__.errno == errno.EIO
    assert not (state_root / "workspace-binding.json").exists()
    assert not list(state_root.glob(".workspace-binding.json-*.tmp"))


def test_binding_write_path_does_not_change_process_umask():
    write_path_source = "\n".join(
        inspect.getsource(function)
        for function in (
            security_paths._create_binding_temporary_file,
            security_paths._publish_binding_manifest,
            security_paths._bind_state_namespace,
        )
    )

    assert "os.umask" not in write_path_source


def test_existing_binding_symlink_fails_closed(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    target = state_root / "binding-target.json"
    target.write_text(
        json.dumps(
            {
                "canonical_workspace": str(workspace.resolve()),
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )
    binding_path = state_root / "workspace-binding.json"
    try:
        os.symlink(target, binding_path)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    with pytest.raises(StateConfigurationError, match="must not be a symlink"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )


def test_existing_binding_non_regular_file_fails_closed(temp_dir):
    workspace = temp_dir / "workspace"
    state_root = temp_dir / "state"
    workspace.mkdir()
    state_root.mkdir()
    (state_root / "workspace-binding.json").mkdir()

    with pytest.raises(StateConfigurationError, match="not a regular file"):
        _load_state_root(
            {"TOOLHUB_STATE_ROOT": str(state_root.resolve())},
            workspace.resolve(),
        )


def test_explicit_state_symlink_resolving_inside_workspace_fails(temp_dir, monkeypatch):
    workspace = temp_dir / "workspace"
    nested_state = workspace / "state"
    alias = temp_dir / "outside-looking-state"
    workspace.mkdir()
    nested_state.mkdir()
    try:
        os.symlink(nested_state, alias, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(workspace.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(alias.absolute()))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(StateConfigurationError, match="must not be a symlink"):
        get_state_root()

    assert list(nested_state.iterdir()) == []


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

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("LOW intrinsic must not launch a contained process")

    monkeypatch.setattr("mcp_toolhub.tools.shell.run_contained_process", fake_run)

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

    result = write_file("link/file.txt", "blocked")

    assert result.outcome == ContractOutcome.REFUSED
    assert result.error.code == "MUTATION_REFUSED"


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
    state_root = temp_dir / "state"
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(temp_dir.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(state_root.resolve()))
    _reset_runtime_configuration_for_tests()

    with pytest.raises(
        RuntimeConfigurationError,
        match="TOOLHUB_STATE_ROOT must be outside",
    ):
        initialize_runtime_configuration()

    assert not state_root.exists()


def test_external_git_repository_integration_smoke_flow(git_repo, run_git, monkeypatch):
    root = _configure(monkeypatch, git_repo)
    (root / "flow.txt").write_text("before\n", encoding="utf-8")
    run_git("add", "flow.txt", cwd=root)
    (root / "flow.txt").write_text("before\nafter\n", encoding="utf-8")

    read = read_file("flow.txt")

    shell_calls = []

    def fake_run(*args, **kwargs):
        shell_calls.append((args, kwargs))
        raise AssertionError("LOW intrinsic must not launch a contained process")

    # Scope the LOW intrinsic guard to this execution before exercising real Git.
    with monkeypatch.context() as shell_patch:
        shell_patch.setattr(
            "mcp_toolhub.tools.shell.run_contained_process",
            fake_run,
        )
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
