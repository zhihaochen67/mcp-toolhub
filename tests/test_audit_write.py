"""Regression coverage for complete, durable trusted audit appends."""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.security import state_permissions
from mcp_toolhub.security.paths import get_state_root
from mcp_toolhub.tools.shell import run_shell

ORIGINAL = b'{ "trace_id": "trc_original", "action": "original" }\r\n'
TIMESTAMP = "2026-09-03T00:00:00+00:00"
POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX trusted-file type and permission semantics"
)


def _record(path, action="追加"):
    return audit.record_event(
        tool="test",
        action=action,
        trace_id="trc_append",
        timestamp=TIMESTAMP,
        audit_path=path,
    )


@pytest.fixture
def audit_patch(temp_dir, isolated_approval_store):
    """Restore shared OS functions before either directory fixture is removed.

    On POSIX, shutil.rmtree uses os.open(..., dir_fd=...) and os.fstat during
    teardown. Audit fault injection must end before that unrelated filesystem IO.
    """
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def test_audit_fault_injection_ends_before_directory_cleanup(request, temp_dir):
    original = {
        name: getattr(os, name)
        for name in ("open", "write", "fsync", "fstat", "ftruncate")
    }
    cleanup = temp_dir / "cleanup"
    nested = cleanup / "nested"
    nested.mkdir(parents=True)
    (nested / "sentinel").write_bytes(b"cleanup must use real OS functions")

    def verify_cleanup():
        for name, function in original.items():
            assert getattr(os, name) is function
        # Linux opens the nested directory relative to its parent descriptor.
        shutil.rmtree(cleanup)
        assert not cleanup.exists()

    # Register cleanup first, then acquire the patch fixture so its finalizer
    # runs before this probe, just as it must precede the directory fixtures.
    request.addfinalizer(verify_cleanup)
    patch = request.getfixturevalue("audit_patch")

    def fail(*_args, **_kwargs):
        raise AssertionError("audit fault injection leaked into fixture cleanup")

    for name in original:
        patch.setattr(audit.os, name, fail)


@pytest.fixture
def opened_files(audit_patch):
    """Track real descriptors and require both log and lock cleanup on every path."""
    opened = []
    real_open, real_fstat = os.open, os.fstat

    def track_open(path, flags, mode=0o777):
        descriptor = real_open(path, flags, mode)
        opened.append((Path(path), descriptor))
        return descriptor

    audit_patch.setattr(audit.os, "open", track_open)
    yield opened
    for _path, descriptor in opened:
        with pytest.raises(OSError) as captured:
            real_fstat(descriptor)
        assert captured.value.errno == errno.EBADF


def test_new_log_uses_exclusive_trusted_creation(temp_dir, audit_patch, opened_files):
    path = temp_dir / "audit.jsonl"
    real_open = os.open
    attempts = []

    def inspect_open(target, flags, mode=0o777):
        if Path(target) == path:
            attempts.append(flags)
            assert flags & os.O_APPEND and flags & os.O_WRONLY
            assert not flags & os.O_TRUNC
            assert mode == 0o600
        return real_open(target, flags, mode)

    audit_patch.setattr(audit.os, "open", inspect_open)
    assert _record(path)
    assert len(attempts) == 2
    assert not attempts[0] & os.O_CREAT
    assert attempts[1] & os.O_CREAT and attempts[1] & os.O_EXCL
    assert {target for target, _fd in opened_files} == {
        path,
        path.with_name("audit.jsonl.lock"),
    }
    assert json.loads(path.read_bytes())["action"] == "追加"


@pytest.mark.parametrize("chunk_size", [None, 1, 7])
def test_complete_utf8_appends_preserve_order_and_fsync_under_lock(
    temp_dir, audit_patch, opened_files, chunk_size
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    real_write, real_fsync = os.write, os.fsync
    writes = []
    synced_actions = []

    def write(descriptor, data):
        assert audit._write_lock.locked()
        count = real_write(descriptor, data[:chunk_size])
        writes.append(count)
        return count

    def sync(descriptor):
        assert audit._write_lock.locked()
        raw = path.read_bytes()
        assert raw.startswith(ORIGINAL) and raw.endswith(b"\n")
        lines = raw.splitlines(keepends=True)
        assert all(line.endswith(b"\n") for line in lines)
        events = [json.loads(line) for line in lines]
        synced_actions.append(events[-1]["action"])
        assert events[-1] == {
            "trace_id": "trc_append",
            "timestamp": TIMESTAMP,
            "tool": "test",
            "action": synced_actions[-1],
        }
        real_fsync(descriptor)

    audit_patch.setattr(audit.os, "write", write)
    audit_patch.setattr(audit.os, "fsync", sync)
    assert _record(path, "追加一")
    assert synced_actions == ["追加一"]
    assert _record(path, "追加二")
    assert synced_actions == ["追加一", "追加二"]
    raw = path.read_bytes()
    assert sum(writes) == len(raw) - len(ORIGINAL)
    assert len(writes) == 2 if chunk_size is None else len(writes) > 2
    assert [json.loads(line)["action"] for line in raw.splitlines()] == [
        "original",
        "追加一",
        "追加二",
    ]


@pytest.mark.parametrize("existed", [False, True])
@pytest.mark.parametrize("stage", ["write", "unreported-write", "fsync"])
@pytest.mark.parametrize(
    "error_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit]
)
def test_failed_append_rolls_back_bytes_closes_descriptors_and_preserves_interrupts(
    temp_dir, audit_patch, opened_files, existed, stage, error_type
):
    path = temp_dir / "audit.jsonl"
    original = ORIGINAL if existed else b""
    if existed:
        path.write_bytes(original)
    real_write, real_fsync, real_truncate = os.write, os.fsync, os.ftruncate
    failure = error_type("simulated audit failure")
    write_calls = 0
    sync_calls = 0
    truncated = []

    def write(descriptor, data):
        nonlocal write_calls
        write_calls += 1
        if stage == "fsync":
            return real_write(descriptor, data)
        if write_calls == 1:
            count = real_write(descriptor, data[:8])
            if stage == "write":
                return count
        raise failure

    def sync(descriptor):
        nonlocal sync_calls
        sync_calls += 1
        assert audit._write_lock.locked()
        if stage == "fsync" and sync_calls == 1:
            assert path.stat().st_size > len(original)
            raise failure
        assert path.read_bytes() == original
        real_fsync(descriptor)

    def truncate(descriptor, size):
        assert audit._write_lock.locked()
        assert path.stat().st_size > size
        truncated.append(size)
        real_truncate(descriptor, size)

    with audit_patch.context() as patch:
        patch.setattr(audit.os, "write", write)
        patch.setattr(audit.os, "fsync", sync)
        patch.setattr(audit.os, "ftruncate", truncate)
        if error_type is OSError:
            assert _record(path) is False
        else:
            with pytest.raises(error_type) as captured:
                _record(path)
            assert captured.value is failure

    assert truncated == [len(original)]
    assert sync_calls == (2 if stage == "fsync" else 1)
    assert path.read_bytes() == original
    assert not audit._write_lock.locked()
    assert len(opened_files) == 2
    # The OS sidecar lock is released as well: a later append can succeed.
    assert _record(path, "recovered")
    assert path.read_bytes().startswith(original)


@pytest.mark.parametrize("progress", [0, -1, "oversized"])
def test_invalid_write_progress_is_nonfatal_and_preserves_existing_bytes(
    temp_dir, audit_patch, opened_files, progress
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)

    def invalid_write(_descriptor, data):
        return len(data) + 1 if progress == "oversized" else progress

    audit_patch.setattr(audit.os, "write", invalid_write)
    assert _record(path) is False
    assert path.read_bytes() == ORIGINAL


@pytest.mark.parametrize("stage", ["ftruncate", "fsync"])
def test_rollback_failure_is_best_effort_and_descriptors_still_close(
    temp_dir, audit_patch, opened_files, stage
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    real_write = os.write
    attempts = []

    def failed_write(descriptor, data):
        real_write(descriptor, data[:8])
        raise OSError(errno.EIO, "write failed after writing bytes")

    def fail_cleanup(*_args):
        attempts.append(stage)
        raise OSError(errno.EIO, "rollback failure")

    audit_patch.setattr(audit.os, "write", failed_write)
    audit_patch.setattr(audit.os, stage, fail_cleanup)
    assert _record(path) is False
    assert attempts == [stage]
    raw = path.read_bytes()
    assert raw.startswith(ORIGINAL)
    assert len(raw) == len(ORIGINAL) + (8 if stage == "ftruncate" else 0)


def test_repeated_fsync_failure_still_truncates(temp_dir, audit_patch, opened_files):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    sizes_at_sync = []

    def fail_sync(_descriptor):
        sizes_at_sync.append(path.stat().st_size)
        raise OSError(errno.EIO, "persistent fsync failure")

    audit_patch.setattr(audit.os, "fsync", fail_sync)
    assert _record(path) is False
    assert len(sizes_at_sync) == 2
    assert sizes_at_sync[0] > sizes_at_sync[1] == len(ORIGINAL)
    assert path.read_bytes() == ORIGINAL


@pytest.mark.parametrize("stage", ["mkdir", "lock", "existing", "create", "stat"])
def test_open_and_size_failures_are_nonfatal_without_changing_existing_bytes(
    temp_dir, audit_patch, opened_files, stage
):
    path = temp_dir / "audit.jsonl"
    if stage != "create":
        path.write_bytes(ORIGINAL)
    trusted_open, real_fstat = audit.open_trusted_file, os.fstat
    audit_descriptors = []

    def open_log(target, flags, mode=0o600):
        if (
            (stage == "lock" and Path(target) != path)
            or (stage == "existing" and Path(target) == path)
            or (stage == "create" and flags & os.O_EXCL)
        ):
            raise PermissionError(errno.EACCES, "simulated open failure")
        descriptor = trusted_open(target, flags, mode)
        if Path(target) == path:
            audit_descriptors.append(descriptor)
        return descriptor

    def fstat(descriptor):
        if descriptor in audit_descriptors:
            raise OSError(errno.EIO, "original size unavailable")
        return real_fstat(descriptor)

    def fail_mkdir(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "parent directory unavailable")

    audit_patch.setattr(audit, "open_trusted_file", open_log)
    if stage == "mkdir":
        audit_patch.setattr(Path, "mkdir", fail_mkdir)
    elif stage == "stat":
        audit_patch.setattr(audit.os, "fstat", fstat)
    assert _record(path) is False
    if stage == "create":
        assert not path.exists()
    else:
        assert path.read_bytes() == ORIGINAL


@pytest.mark.parametrize(
    "error_type", [TypeError, ValueError, MemoryError, KeyboardInterrupt, SystemExit]
)
def test_serialization_failure_does_not_open_or_modify_log(
    temp_dir, audit_patch, opened_files, error_type
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    failure = error_type("serialization failed")

    def fail(*_args, **_kwargs):
        raise failure

    audit_patch.setattr(audit.json, "dumps", fail)
    if error_type in (TypeError, ValueError):
        assert _record(path) is False
    else:
        with pytest.raises(error_type) as captured:
            _record(path)
        assert captured.value is failure
    assert not opened_files
    assert path.read_bytes() == ORIGINAL


def test_encoding_failure_precedes_open(temp_dir, opened_files):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    assert _record(path, "\ud800") is False
    assert not opened_files
    assert path.read_bytes() == ORIGINAL


def test_creation_collision_reopens_existing_log_through_trusted_primitive(
    temp_dir, audit_patch, opened_files
):
    path = temp_dir / "audit.jsonl"
    trusted_open = audit.open_trusted_file
    attempts = []

    def race_open(target, flags, mode=0o600):
        if Path(target) == path:
            attempts.append(flags)
            if flags & os.O_EXCL:
                path.write_bytes(ORIGINAL)
        return trusted_open(target, flags, mode)

    audit_patch.setattr(audit, "open_trusted_file", race_open)
    assert _record(path)
    assert len(attempts) == 3
    assert not attempts[-1] & os.O_CREAT
    assert path.read_bytes().startswith(ORIGINAL)
    assert len(path.read_bytes().splitlines()) == 2


@POSIX_ONLY
@pytest.mark.parametrize("existed", [False, True])
def test_successful_append_normalizes_log_and_lock_to_exactly_0600(temp_dir, existed):
    path = temp_dir / "audit.jsonl"
    lock = path.with_name("audit.jsonl.lock")
    if existed:
        path.write_bytes(ORIGINAL)
        lock.touch()
        os.chmod(path, 0o666)
        os.chmod(lock, 0o666)
    assert _record(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    if existed:
        assert path.read_bytes().startswith(ORIGINAL)


@POSIX_ONLY
@pytest.mark.parametrize("existed", [False, True])
def test_permission_normalization_failure_closes_audit_descriptor(
    temp_dir, audit_patch, opened_files, existed
):
    path = temp_dir / "audit.jsonl"
    if existed:
        path.write_bytes(ORIGINAL)
    secure_descriptor = state_permissions.secure_trusted_file_descriptor

    def fail_audit_permissions(descriptor):
        if (path, descriptor) in opened_files:
            raise PermissionError(errno.EACCES, "audit permissions unavailable")
        secure_descriptor(descriptor)

    audit_patch.setattr(
        state_permissions, "secure_trusted_file_descriptor", fail_audit_permissions
    )
    assert _record(path) is False
    assert path.read_bytes() == (ORIGINAL if existed else b"")
    assert len(opened_files) == 2


@POSIX_ONLY
@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("kind", ["symlink", "dangling-symlink", "creation-race"])
def test_final_symlink_is_rejected_without_touching_target(
    temp_dir, audit_patch, opened_files, fallback, kind
):
    path = temp_dir / "audit.jsonl"
    target = temp_dir / "target.jsonl"
    if kind != "dangling-symlink":
        target.write_bytes(ORIGINAL)
        os.chmod(target, 0o644)
    if kind != "creation-race":
        path.symlink_to(target)
    trusted_open = audit.open_trusted_file

    def race_open(location, flags, mode=0o600):
        if Path(location) == path and flags & os.O_EXCL:
            path.symlink_to(target)
        return trusted_open(location, flags, mode)

    if fallback:
        audit_patch.setattr(state_permissions.os, "O_NOFOLLOW", 0, raising=False)
    if kind == "creation-race":
        audit_patch.setattr(audit, "open_trusted_file", race_open)
    assert _record(path) is False
    assert path.is_symlink()
    if kind == "dangling-symlink":
        assert not target.exists()
    else:
        assert target.read_bytes() == ORIGINAL
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_directory_is_rejected(temp_dir, opened_files):
    path = temp_dir / "audit.jsonl"
    path.mkdir()
    assert _record(path) is False
    assert path.is_dir()


@POSIX_ONLY
def test_fifo_is_rejected_without_blocking_or_chmod(
    temp_dir, audit_patch, opened_files
):
    path = temp_dir / "audit.jsonl"
    os.mkfifo(path, 0o644)
    original_mode = path.stat().st_mode
    real_open = os.open

    def require_nonblocking(target, flags, mode=0o777):
        if Path(target) == path:
            assert flags & os.O_NONBLOCK  # Fail deterministically instead of hanging.
        return real_open(target, flags, mode)

    audit_patch.setattr(audit.os, "open", require_nonblocking)
    assert _record(path) is False
    assert path.stat().st_mode == original_mode


@pytest.mark.parametrize("stage", ["open", "write", "fsync"])
def test_audit_failure_during_real_tool_execution_is_nonfatal(audit_patch, stage):
    path = get_state_root() / "audit.jsonl"
    path.write_bytes(ORIGINAL)
    trusted_open = audit.open_trusted_file
    real_write = os.write

    def fail(*args, **_kwargs):
        if stage == "write":
            real_write(args[0], args[1][:8])
        raise OSError(errno.EIO, "simulated audit failure")

    def open_log(target, flags, mode=0o600):
        if Path(target) == path:
            fail()
        return trusted_open(target, flags, mode)

    with audit_patch.context() as patch:
        if stage == "open":
            patch.setattr(audit, "open_trusted_file", open_log)
        else:
            patch.setattr(audit.os, stage, fail)
        result = run_shell("python", ["--version"])
    assert result.executed is True
    assert result.returncode == 0
    assert path.read_bytes() == ORIGINAL


def test_audit_write_never_changes_process_umask(temp_dir, audit_patch):
    calls = []

    def forbidden_umask(*_args):
        calls.append("umask")
        raise AssertionError("audit must not change the process umask")

    audit_patch.setattr(audit.os, "umask", forbidden_umask)
    assert _record(temp_dir / "audit.jsonl")
    assert not calls
    source_root = Path(audit.__file__).parents[1]
    for source in source_root.rglob("*.py"):
        assert "os.umask" not in source.read_text(encoding="utf-8")
