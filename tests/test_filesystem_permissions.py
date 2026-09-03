"""Workspace replacement modes, private staging, and pre-publication failures."""

from __future__ import annotations

import builtins
import errno
import hashlib
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.tools import filesystem

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX mode/fchmod assertions do not apply to Windows ACLs",
)
PATCH = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-old\n+new\n"


def _request(root, operation):
    expected = hashlib.sha256(b"old\n").hexdigest()
    if operation == "write":
        pending = filesystem.write_file("file.txt", "new\n", expected, root=root)
        resume = filesystem.write_file_approved
    else:
        pending = filesystem.apply_patch("file.txt", PATCH, expected, root=root)
        resume = filesystem.apply_patch_approved
    assert pending.outcome == ContractOutcome.APPROVAL_REQUIRED
    assert (root / "file.txt").read_bytes() == b"old\n"
    approval.approve_request(pending.request_id)
    return pending, resume


@POSIX_ONLY
@pytest.mark.parametrize("operation", ["write", "patch"])
@pytest.mark.parametrize(
    ("mode", "expected_mode"),
    [
        pytest.param(0o600, 0o600, id="0600-preserved"),
        pytest.param(0o640, 0o640, id="0640-preserved"),
        pytest.param(0o644, 0o644, id="0644-preserved"),
        pytest.param(0o755, 0o755, id="0755-preserved"),
        pytest.param(0o700, 0o700, id="0700-preserved"),
        pytest.param(0o4755, 0o755, id="setuid-cleared"),
        pytest.param(0o2755, 0o755, id="setgid-cleared"),
        pytest.param(0o1755, 0o755, id="sticky-cleared"),
        pytest.param(0o6751, 0o751, id="setuid-setgid-cleared"),
        pytest.param(0o5740, 0o740, id="setuid-sticky-cleared"),
        pytest.param(0o3640, 0o640, id="setgid-sticky-cleared"),
        pytest.param(0o7700, 0o700, id="all-special-bits-cleared"),
    ],
)
def test_approved_replacement_preserves_only_rwx_permissions(
    temp_dir, operation, mode, expected_mode
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"old\n")
    target.chmod(mode)
    assert stat.S_IMODE(target.stat().st_mode) == mode
    pending, resume = _request(temp_dir, operation)

    done = resume(pending.request_id, root=temp_dir)

    assert done.outcome == ContractOutcome.SUCCEEDED
    assert done.executed is True
    assert target.read_bytes() == b"new\n"
    assert stat.S_IMODE(target.stat().st_mode) == expected_mode
    assert stat.S_ISREG(target.stat().st_mode)
    assert not list(temp_dir.glob(".*.tmp"))
    assert resume(pending.request_id, root=temp_dir).executed is False


@POSIX_ONLY
@pytest.mark.parametrize("operation", ["write", "patch"])
def test_mode_comes_from_execution_target_not_approval_time(temp_dir, operation):
    target = temp_dir / "file.txt"
    target.write_bytes(b"old\n")
    target.chmod(0o644)
    pending, resume = _request(temp_dir, operation)
    target.chmod(0o600)

    assert resume(pending.request_id, root=temp_dir).executed is True
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@POSIX_ONLY
def test_approved_new_file_has_deterministic_private_nonexecutable_mode(temp_dir):
    pending = filesystem.write_file(
        "nested/new.txt", "private", create_parents=True, root=temp_dir
    )
    assert not (temp_dir / "nested").exists()
    approval.approve_request(pending.request_id)

    done = filesystem.write_file_approved(pending.request_id, root=temp_dir)

    assert done.outcome == ContractOutcome.SUCCEEDED
    assert done.created is True
    target = temp_dir / "nested/new.txt"
    assert target.read_bytes() == b"private"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@POSIX_ONLY
@pytest.mark.parametrize(
    ("mode", "expected_mode"), [(0o600, 0o600), (0o755, 0o755), (0o7751, 0o751)]
)
def test_temp_is_private_until_content_is_ready_and_fsynced_before_publish(
    temp_dir, monkeypatch, mode, expected_mode
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    target.chmod(mode)
    real_open = builtins.open
    real_set_mode = filesystem._set_replacement_mode
    real_fsync, real_replace = os.fsync, os.replace
    observations = []

    def inspect_open(*args, **kwargs):
        handle = real_open(*args, **kwargs)
        metadata = os.fstat(handle.fileno())
        assert stat.S_IMODE(metadata.st_mode) & ~0o600 == 0
        assert metadata.st_size == 0
        observations.append("private_creation")
        return handle

    def inspect_mode(descriptor, desired):
        assert desired & ~0o777 == 0
        metadata = os.fstat(descriptor)
        if metadata.st_size:
            assert stat.S_IMODE(metadata.st_mode) == 0o600
            assert metadata.st_size == len(b"replacement")
            assert target.read_bytes() == b"original"
            observations.append("private_content")
        real_set_mode(descriptor, desired)

    def inspect_fsync(descriptor):
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == expected_mode
        real_fsync(descriptor)
        observations.append("fsync")

    def inspect_replace(source, destination):
        assert Path(source).parent == target.parent
        assert Path(destination) == target
        assert stat.S_IMODE(Path(source).stat().st_mode) == expected_mode
        assert Path(source).read_bytes() == b"replacement"
        assert target.read_bytes() == b"original"
        assert observations == ["private_creation", "private_content", "fsync"]
        real_replace(source, destination)
        observations.append("publish")

    monkeypatch.setattr(filesystem, "open", inspect_open, raising=False)
    monkeypatch.setattr(filesystem, "_set_replacement_mode", inspect_mode)
    monkeypatch.setattr(os, "fsync", inspect_fsync)
    monkeypatch.setattr(os, "replace", inspect_replace)

    filesystem._atomic_write_text(target, "replacement")

    assert observations[-1] == "publish"


@POSIX_ONLY
@pytest.mark.parametrize("mask", [0, 0o777])
def test_modes_are_independent_of_umask_in_isolated_process(temp_dir, mask):
    # Changing umask is confined to this child, never to the pytest process.
    script = textwrap.dedent("""
        import builtins
        import os
        import stat
        import sys
        from pathlib import Path
        from mcp_toolhub.tools import filesystem

        root = Path(sys.argv[1])
        for mode in (0o600, 0o640, 0o751):
            target = root / f'existing-{mode:o}'
            target.write_bytes(b'original')
            target.chmod(mode)

        real_open = builtins.open
        real_set_mode = filesystem._set_replacement_mode
        observed = []
        def inspect_open(*args, **kwargs):
            handle = real_open(*args, **kwargs)
            assert stat.S_IMODE(os.fstat(handle.fileno()).st_mode) & ~0o600 == 0
            observed.append('private_creation')
            return handle
        def inspect_mode(descriptor, mode):
            real_set_mode(descriptor, mode)
            assert stat.S_IMODE(os.fstat(descriptor).st_mode) == mode
        filesystem.open = inspect_open
        filesystem._set_replacement_mode = inspect_mode
        os.umask(int(sys.argv[2]))
        for mode in (0o600, 0o640, 0o751):
            target = root / f'existing-{mode:o}'
            filesystem._atomic_write_text(target, 'replacement')
            assert target.read_bytes() == b'replacement'
            assert stat.S_IMODE(target.stat().st_mode) == mode
        target = root / 'new'
        filesystem._atomic_write_text(target, 'private')
        assert target.read_bytes() == b'private'
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert len(observed) == 4
        assert not list(root.glob('.*.tmp'))
    """)
    result = subprocess.run(
        [sys.executable, "-c", script, str(temp_dir), str(mask)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@POSIX_ONLY
@pytest.mark.parametrize("stage", [1, 2], ids=["private-mode", "final-mode"])
@pytest.mark.parametrize(
    "error_type", [PermissionError, MemoryError, KeyboardInterrupt, SystemExit]
)
def test_permission_failure_cleans_temp_and_propagates_original_exception(
    temp_dir, monkeypatch, stage, error_type
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    target.chmod(0o640)
    before = target.stat()
    failure = error_type("injected fchmod failure")
    real_fchmod = os.fchmod
    calls = 0

    def fail_mode(descriptor, mode):
        nonlocal calls
        calls += 1
        if calls == stage:
            raise failure
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", fail_mode)

    with pytest.raises(error_type) as caught:
        filesystem._atomic_write_text(target, "replacement")

    assert caught.value is failure
    assert target.read_bytes() == b"original"
    assert os.path.samestat(before, target.stat())
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not list(temp_dir.glob(".*.tmp"))


@POSIX_ONLY
@pytest.mark.parametrize("operation", ["write", "patch"])
def test_permission_failure_uses_existing_mutation_error_model(
    temp_dir, monkeypatch, operation
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"old\n")
    pending, resume = _request(temp_dir, operation)

    def fail_mode(*_args):
        raise PermissionError(errno.EPERM, "injected permission failure")

    # Patch the workspace helper, leaving approval-store mode setup unaffected.
    monkeypatch.setattr(filesystem, "_set_replacement_mode", fail_mode)
    done = resume(pending.request_id, root=temp_dir)

    assert done.outcome == ContractOutcome.FAILED
    assert done.executed is False
    assert done.error.code == f"FILE_{operation.upper()}_FAILED"
    assert done.approval_status == ApprovalStatus.CONSUMED
    assert target.read_bytes() == b"old\n"
    assert not list(temp_dir.glob(".*.tmp"))
    event = audit.read_recent(limit=1)[-1]
    assert event["error_type"] == "PermissionError"
    assert "injected permission failure" in event["error"]


@pytest.mark.parametrize("stage", ["fsync", "replace"])
@pytest.mark.parametrize("existing", [False, True])
def test_publication_failure_preserves_target_and_cleans_temp(
    temp_dir, monkeypatch, stage, existing
):
    target = temp_dir / "file.txt"
    if existing:
        target.write_bytes(b"original")
    failure = OSError(errno.EIO, f"injected {stage} failure")

    def fail(*_args):
        raise failure

    monkeypatch.setattr(os, stage, fail)
    with pytest.raises(OSError) as caught:
        filesystem._atomic_write_text(target, "replacement")

    assert caught.value is failure
    assert target.read_bytes() == b"original" if existing else not target.exists()
    assert not list(temp_dir.glob(".*.tmp"))


@pytest.mark.parametrize(
    "change", ["inode", "disappear", "appear", "content", "directory"]
)
def test_target_changes_during_preparation_fail_closed(temp_dir, monkeypatch, change):
    target = temp_dir / "file.txt"
    if change != "appear":
        target.write_bytes(b"original")
    incoming = temp_dir / "incoming"
    incoming.write_bytes(b"unrelated inode")
    real_fsync = os.fsync

    def change_target(descriptor):
        real_fsync(descriptor)
        if change == "inode":
            os.replace(incoming, target)
        elif change == "disappear":
            target.unlink()
        elif change == "directory":
            target.unlink()
            target.mkdir()
        else:
            target.write_bytes(b"concurrent content")

    monkeypatch.setattr(os, "fsync", change_target)
    with pytest.raises(ValueError, match="changed|regular file"):
        filesystem._atomic_write_text(target, "replacement")

    if change == "directory":
        assert target.is_dir()
    elif change == "disappear":
        assert not target.exists()
    else:
        expected = b"unrelated inode" if change == "inode" else b"concurrent content"
        assert target.read_bytes() == expected
    assert not list(temp_dir.glob(".*.tmp"))


@POSIX_ONLY
def test_concurrent_mode_tightening_is_not_overwritten(temp_dir, monkeypatch):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    target.chmod(0o644)
    real_fsync = os.fsync

    def tighten_mode(descriptor):
        real_fsync(descriptor)
        target.chmod(0o600)

    monkeypatch.setattr(os, "fsync", tighten_mode)
    with pytest.raises(filesystem.MutationConflictError):
        filesystem._atomic_write_text(target, "replacement")

    assert target.read_bytes() == b"original"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(temp_dir.glob(".*.tmp"))


def test_temp_name_collision_does_not_delete_unowned_file(temp_dir, monkeypatch):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    collision = temp_dir / ".file.txt.fixed.tmp"
    collision.write_bytes(b"not our temporary file")
    monkeypatch.setattr(filesystem.secrets, "token_hex", lambda _size: "fixed")

    with pytest.raises(FileExistsError):
        filesystem._atomic_write_text(target, "replacement")

    assert target.read_bytes() == b"original"
    assert collision.read_bytes() == b"not our temporary file"


def test_swapped_temp_is_neither_published_nor_deleted(temp_dir, monkeypatch):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    incoming = temp_dir / "incoming"
    incoming.write_bytes(b"unowned temporary file")
    real_check = filesystem._check_replacement_target
    checks = 0
    swapped = None

    def swap_temp_after_close(path, before):
        nonlocal checks, swapped
        checks += 1
        if checks == 2:
            swapped = next(temp_dir.glob(".*.tmp"))
            os.replace(incoming, swapped)
        real_check(path, before)

    monkeypatch.setattr(filesystem, "_check_replacement_target", swap_temp_after_close)
    with pytest.raises(
        filesystem.MutationConflictError, match="temporary file changed"
    ):
        filesystem._atomic_write_text(target, "replacement")

    assert target.read_bytes() == b"original"
    assert swapped.read_bytes() == b"unowned temporary file"


@POSIX_ONLY
def test_unapplied_final_mode_prevents_publication(temp_dir, monkeypatch):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    target.chmod(0o640)
    real_fchmod = os.fchmod

    def silently_ignore_final_mode(descriptor, mode):
        if mode == 0o600:
            real_fchmod(descriptor, mode)

    monkeypatch.setattr(os, "fchmod", silently_ignore_final_mode)
    with pytest.raises(PermissionError, match="permissions could not be set"):
        filesystem._atomic_write_text(target, "replacement")

    assert target.read_bytes() == b"original"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not list(temp_dir.glob(".*.tmp"))


@POSIX_ONLY
@pytest.mark.parametrize("kind", ["symlink", "dangling-symlink", "fifo"])
def test_unsafe_target_types_are_rejected_without_following(temp_dir, kind):
    target = temp_dir / "file.txt"
    other = temp_dir / "other.txt"
    if kind == "fifo":
        os.mkfifo(target)
    else:
        if kind == "symlink":
            other.write_bytes(b"private referent")
            other.chmod(0o600)
        target.symlink_to(other)

    for request in (
        lambda: filesystem.write_file("file.txt", "new", root=temp_dir),
        lambda: filesystem.apply_patch("file.txt", PATCH, root=temp_dir),
    ):
        result = request()
        assert result.outcome == ContractOutcome.REFUSED
        assert result.request_id is None
    with pytest.raises(ValueError, match="regular file"):
        filesystem._atomic_write_text(target, "replacement")
    if kind == "symlink":
        assert other.read_bytes() == b"private referent"
        assert stat.S_IMODE(other.stat().st_mode) == 0o600
    else:
        assert not other.exists()
    assert not list(temp_dir.glob(".*.tmp"))


@POSIX_ONLY
def test_symlink_swap_before_publication_leaves_referent_untouched(
    temp_dir, monkeypatch
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"original")
    other = temp_dir / "other.txt"
    other.write_bytes(b"private referent")
    other.chmod(0o600)
    real_fsync = os.fsync

    def swap_target(descriptor):
        real_fsync(descriptor)
        target.unlink()
        target.symlink_to(other)

    monkeypatch.setattr(os, "fsync", swap_target)
    with pytest.raises(ValueError, match="regular file"):
        filesystem._atomic_write_text(target, "replacement")

    assert target.is_symlink()
    assert other.read_bytes() == b"private referent"
    assert stat.S_IMODE(other.stat().st_mode) == 0o600
    assert not list(temp_dir.glob(".*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="Windows behavior without POSIX chmod")
@pytest.mark.parametrize("operation", ["write", "patch"])
def test_windows_approved_mutations_do_not_apply_posix_modes(
    temp_dir, monkeypatch, operation
):
    target = temp_dir / "file.txt"
    target.write_bytes(b"old\n")
    pending, resume = _request(temp_dir, operation)

    def forbidden_mode(*_args):
        pytest.fail("POSIX mode setup must not run on Windows")

    monkeypatch.setattr(filesystem, "_set_replacement_mode", forbidden_mode)
    done = resume(pending.request_id, root=temp_dir)
    assert done.outcome == ContractOutcome.SUCCEEDED
    assert target.read_bytes() == b"new\n"
    pending = filesystem.write_file("new.txt", "new\r\n", root=temp_dir)
    approval.approve_request(pending.request_id)
    assert filesystem.write_file_approved(pending.request_id, root=temp_dir).executed
    assert (temp_dir / "new.txt").read_bytes() == b"new\r\n"
    assert not list(temp_dir.glob(".*.tmp"))
