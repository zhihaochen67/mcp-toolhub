"""Failure and race regressions for publishing the trusted approval store."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest
from pydantic_core import PydanticSerializationError

from mcp_toolhub.security import approval
from mcp_toolhub.security.risk import RiskLevel

ORIGINAL = b'{"version":2,"requests":{}}\n'
REPLACEMENT = b'{\n  "version": 2,\n  "requests": {}\n}'
POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX descriptor identity and permission semantics"
)


def _assert_preserved(store_path, existed=True):
    if existed:
        assert store_path.read_bytes() == ORIGINAL
    else:
        assert not store_path.exists()
    assert not list(store_path.parent.glob(".approvals-*.tmp"))


def _symlink(target, link):
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlink creation is unavailable: {exc}")


@pytest.mark.parametrize("chunk_size", [1, 7])
def test_short_writes_finish_and_fsync_precedes_atomic_publication(
    temp_dir, monkeypatch, chunk_size
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    real_write, real_fsync, real_replace = os.write, os.fsync, os.replace
    writes = []
    events = []

    def short_write(descriptor, data):
        assert store_path.read_bytes() == ORIGINAL
        count = real_write(descriptor, data[:chunk_size])
        writes.append(count)
        return count

    def sync(descriptor):
        assert sum(writes) == len(REPLACEMENT)
        events.append("fsync")
        real_fsync(descriptor)

    def publish(source, destination):
        assert events == ["fsync"]
        assert Path(source).parent == store_path.parent
        assert Path(source).read_bytes() == REPLACEMENT
        assert store_path.read_bytes() == ORIGINAL
        events.append("replace")
        real_replace(source, destination)

    with monkeypatch.context() as patch:
        patch.setattr(approval.os, "write", short_write)
        patch.setattr(approval.os, "fsync", sync)
        patch.setattr(approval.os, "replace", publish)
        approval._write_serialized_store(store_path, REPLACEMENT)

    assert len(writes) > 1
    assert events == ["fsync", "replace"]
    assert store_path.read_bytes() == REPLACEMENT
    assert approval._read_store(store_path) == {}
    assert not list(temp_dir.glob(".approvals-*.tmp"))


@pytest.mark.parametrize("existed", [False, True])
@pytest.mark.parametrize("stage", ["permissions", "write", "fsync", "replace"])
@pytest.mark.parametrize("error_type", [OSError, MemoryError, KeyboardInterrupt])
def test_failed_publication_preserves_store_cleans_owned_temp_and_closes_descriptors(
    temp_dir, monkeypatch, existed, stage, error_type
):
    store_path = temp_dir / "approvals.json"
    if existed:
        store_path.write_bytes(ORIGINAL)
    failure = (
        OSError(errno.EIO, "simulated private failure")
        if error_type is OSError
        else error_type("simulated private failure")
    )
    real_open, real_write = os.open, os.write
    descriptors = []

    def track_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def fail(*args):
        if stage == "write":
            real_write(args[0], args[1][:3])
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(approval.os, "open", track_open)
        if stage == "permissions":
            patch.setattr(approval, "secure_trusted_file_descriptor", fail)
        else:
            patch.setattr(approval.os, stage, fail)
        expected = approval.ApprovalStoreError if error_type is OSError else error_type
        with pytest.raises(expected) as captured:
            approval._write_serialized_store(store_path, REPLACEMENT)

    if error_type is OSError:
        assert captured.value.__cause__ is failure
        assert "private failure" not in str(captured.value)
    else:
        assert captured.value is failure
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    _assert_preserved(store_path, existed)


@pytest.mark.parametrize("count", [0, -1, len(REPLACEMENT) + 1])
def test_invalid_write_progress_fails_closed(temp_dir, monkeypatch, count):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    monkeypatch.setattr(approval.os, "write", lambda *_args: count)
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert captured.value.__cause__.errno == errno.EIO
    _assert_preserved(store_path)


@pytest.mark.parametrize("stage", ["model", "json", "encoding"])
@pytest.mark.parametrize(
    "error_type", [TypeError, ValueError, OverflowError, RecursionError, MemoryError]
)
def test_guarded_serialization_preserves_store_without_opening_temp(
    temp_dir, monkeypatch, stage, error_type
):
    store_path = temp_dir / "approvals.json"
    request = approval.create_request(
        risk=RiskLevel.MEDIUM, risk_reason="test", store_path=store_path
    )
    original = store_path.read_bytes()
    failure = error_type("private payload must not appear in the store diagnostic")

    def fail(*_args, **_kwargs):
        raise failure

    class Unencodable(str):
        encode = fail

    with monkeypatch.context() as patch:
        if stage == "model":
            patch.setattr(approval.ApprovalRequest, "model_dump", fail)
        elif stage == "json":
            patch.setattr(approval.json, "dumps", fail)
        else:
            patch.setattr(approval.json, "dumps", lambda *_a, **_k: Unencodable())
        expected = (
            MemoryError if error_type is MemoryError else approval.ApprovalStoreError
        )
        with pytest.raises(expected) as captured:
            approval._write_store(store_path, {request.request_id: request})

    if error_type is MemoryError:
        assert captured.value is failure
    else:
        assert captured.value.__cause__ is failure
        assert str(captured.value) == "Approval store could not be serialized."
    assert store_path.read_bytes() == original
    assert not list(temp_dir.glob(".approvals-*.tmp"))


def test_create_request_with_unserializable_payload_preserves_store(temp_dir):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval.create_request(
            risk=RiskLevel.MEDIUM,
            risk_reason="test",
            payload={"unsupported": object()},
            store_path=store_path,
        )
    assert isinstance(captured.value.__cause__, PydanticSerializationError)
    _assert_preserved(store_path)


def test_utf8_encoding_failure_preserves_store(temp_dir, monkeypatch):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    monkeypatch.setattr(approval.json, "dumps", lambda *_a, **_k: "\ud800")
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_store(store_path, {})
    assert isinstance(captured.value.__cause__, UnicodeEncodeError)
    _assert_preserved(store_path)


def test_directory_creation_failure_is_wrapped(temp_dir, monkeypatch):
    store_path = temp_dir / "missing" / "approvals.json"
    failure = PermissionError(errno.EACCES, "simulated directory failure")

    def fail(*_args, **_kwargs):
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(Path, "mkdir", fail)
        with pytest.raises(approval.ApprovalStoreError) as captured:
            approval._write_serialized_store(store_path, REPLACEMENT)
    assert captured.value.__cause__ is failure
    assert not store_path.parent.exists()


@pytest.mark.parametrize("collision_kind", ["file", "directory", "symlink"])
def test_exclusive_temp_collision_never_removes_unrelated_object(
    temp_dir, monkeypatch, collision_kind
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    collision = temp_dir / ".approvals-collision.tmp"
    sentinel = temp_dir / "unrelated"
    sentinel.write_bytes(b"unrelated")
    if collision_kind == "directory":
        collision.mkdir()
    elif collision_kind == "symlink":
        _symlink(sentinel, collision)
    else:
        collision.write_bytes(b"unrelated")
    before = collision.lstat()
    monkeypatch.setattr(approval.secrets, "token_hex", lambda _length: "collision")
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_serialized_store(store_path, REPLACEMENT)
    # Windows reports a colliding directory as EACCES rather than EEXIST.
    expected = (
        PermissionError
        if os.name == "nt" and collision_kind == "directory"
        else FileExistsError
    )
    assert isinstance(captured.value.__cause__, expected)
    after = collision.lstat()
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    assert sentinel.read_bytes() == b"unrelated"
    assert store_path.read_bytes() == ORIGINAL
    if collision_kind == "file":
        assert collision.read_bytes() == b"unrelated"
    elif collision_kind == "symlink":
        assert collision.is_symlink()
    else:
        assert collision.is_dir()


def test_failed_open_does_not_infer_temp_ownership_from_error_number(
    temp_dir, monkeypatch
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    collision = temp_dir / ".approvals-collision.tmp"
    collision.write_bytes(b"unrelated")
    real_open = os.open
    failure = PermissionError(errno.EACCES, "simulated failed open")

    def fail_temp_open(path, flags, mode=0o600):
        if Path(path) == collision:
            assert flags & os.O_EXCL and flags & os.O_CREAT
            assert mode == 0o600
            raise failure
        return real_open(path, flags, mode)

    monkeypatch.setattr(approval.secrets, "token_hex", lambda _length: "collision")
    with monkeypatch.context() as patch:
        patch.setattr(approval.os, "open", fail_temp_open)
        with pytest.raises(approval.ApprovalStoreError) as captured:
            approval._write_serialized_store(store_path, REPLACEMENT)
    assert captured.value.__cause__ is failure
    assert collision.read_bytes() == b"unrelated"
    assert store_path.read_bytes() == ORIGINAL


def test_cleanup_does_not_unlink_a_replacement_at_owned_temp_name(
    temp_dir, monkeypatch
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    moved_temp = temp_dir / "moved-owned-temp"
    real_replace = os.replace
    replaced_paths = []

    def fail_publication(source, _destination):
        real_replace(source, moved_temp)
        Path(source).write_bytes(b"unrelated replacement")
        replaced_paths.append(Path(source))
        raise OSError(errno.EIO, "simulated publication failure after temp swap")

    monkeypatch.setattr(approval.os, "replace", fail_publication)
    with pytest.raises(approval.ApprovalStoreError):
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert len(replaced_paths) == 1
    assert replaced_paths[0].read_bytes() == b"unrelated replacement"
    assert moved_temp.read_bytes() == REPLACEMENT
    assert store_path.read_bytes() == ORIGINAL


@pytest.mark.parametrize("target_kind", ["directory", "symlink", "dangling-symlink"])
def test_publication_rejects_nonregular_target(temp_dir, target_kind):
    store_path = temp_dir / "approvals.json"
    sentinel = temp_dir / "unrelated.json"
    if target_kind == "directory":
        store_path.mkdir()
    else:
        if target_kind == "symlink":
            sentinel.write_bytes(b"unrelated")
        _symlink(sentinel, store_path)
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert isinstance(captured.value.__cause__, OSError)
    assert not list(temp_dir.glob(".approvals-*.tmp"))
    if target_kind == "directory":
        assert store_path.is_dir()
    else:
        assert store_path.is_symlink()
        if target_kind == "symlink":
            assert sentinel.read_bytes() == b"unrelated"
        else:
            assert not sentinel.exists()


@pytest.mark.parametrize("race", ["appears", "disappears", "replaced", "symlink"])
def test_target_races_during_write_prevent_publication(temp_dir, monkeypatch, race):
    store_path = temp_dir / "approvals.json"
    if race != "appears":
        store_path.write_bytes(ORIGINAL)
    original_location = temp_dir / "original-store"
    incoming = temp_dir / "incoming-store"
    sentinel = temp_dir / "unrelated"
    sentinel.write_bytes(b"unrelated")
    if race == "symlink":
        _symlink(sentinel, incoming)
    else:
        incoming.write_bytes(b"replacement from another writer")
    real_fsync = os.fsync

    def change_target(descriptor):
        real_fsync(descriptor)
        if race != "appears":
            store_path.rename(original_location)
        if race != "disappears":
            incoming.rename(store_path)

    monkeypatch.setattr(approval.os, "fsync", change_target)
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert isinstance(captured.value.__cause__, OSError)
    if race == "appears":
        assert isinstance(captured.value.__cause__, FileExistsError)
    elif race == "disappears":
        assert isinstance(captured.value.__cause__, FileNotFoundError)
    if race != "appears":
        assert original_location.read_bytes() == ORIGINAL
    if race == "symlink":
        assert store_path.is_symlink()
    elif race != "disappears":
        assert store_path.read_bytes() == b"replacement from another writer"
    else:
        assert not store_path.exists()
    assert sentinel.read_bytes() == b"unrelated"
    assert not list(temp_dir.glob(".approvals-*.tmp"))


@POSIX_ONLY
@pytest.mark.parametrize("mask", [0, 0o777])
def test_temporary_permissions_are_trusted_before_writing_and_publication(
    temp_dir, monkeypatch, mask
):
    store_path = temp_dir / "approvals.json"
    real_write, real_replace = os.write, os.replace
    observations = []

    def inspect_write(descriptor, data):
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
        observations.append("write")
        return real_write(descriptor, data)

    def inspect_replace(source, destination):
        assert stat.S_IMODE(Path(source).stat().st_mode) == 0o600
        observations.append("replace")
        return real_replace(source, destination)

    with monkeypatch.context() as patch:
        patch.setattr(approval.os, "write", inspect_write)
        patch.setattr(approval.os, "replace", inspect_replace)
        previous = os.umask(mask)
        try:
            approval._write_serialized_store(store_path, REPLACEMENT)
        finally:
            os.umask(previous)
    assert observations == ["write", "replace"]
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600


@POSIX_ONLY
def test_target_descriptor_pins_original_inode_until_publication(temp_dir, monkeypatch):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    real_open, real_replace = approval.open_trusted_file, os.replace
    target_descriptors = []

    def track_target(path, flags):
        descriptor = real_open(path, flags)
        if path == store_path:
            target_descriptors.append(descriptor)
        return descriptor

    def check_pinned(source, destination):
        assert len(target_descriptors) == 1
        before = os.fstat(target_descriptors[0])
        real_replace(source, destination)
        after = os.fstat(target_descriptors[0])
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        assert os.read(target_descriptors[0], len(ORIGINAL)) == ORIGINAL

    monkeypatch.setattr(approval, "open_trusted_file", track_target)
    monkeypatch.setattr(approval.os, "replace", check_pinned)
    approval._write_serialized_store(store_path, REPLACEMENT)
    with pytest.raises(OSError):
        os.fstat(target_descriptors[0])


@POSIX_ONLY
def test_replaced_target_is_not_chmodded_during_final_identity_check(
    temp_dir, monkeypatch
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    incoming = temp_dir / "incoming"
    incoming.write_bytes(b"unrelated")
    incoming.chmod(0o644)
    real_fsync = os.fsync

    def change_target(descriptor):
        real_fsync(descriptor)
        os.replace(incoming, store_path)

    monkeypatch.setattr(approval.os, "fsync", change_target)
    with pytest.raises(approval.ApprovalStoreError):
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o644
    assert store_path.read_bytes() == b"unrelated"


@POSIX_ONLY
@pytest.mark.parametrize("nofollow", [True, False])
def test_symlink_target_permissions_are_untouched(temp_dir, monkeypatch, nofollow):
    store_path = temp_dir / "approvals.json"
    target = temp_dir / "unrelated"
    target.write_bytes(b"unrelated")
    target.chmod(0o644)
    _symlink(target, store_path)
    if not nofollow:
        monkeypatch.delattr(approval.os, "O_NOFOLLOW", raising=False)
    with pytest.raises(approval.ApprovalStoreError):
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert store_path.is_symlink()
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert target.read_bytes() == b"unrelated"


@POSIX_ONLY
def test_target_replacement_during_trusted_open_is_rejected(temp_dir, monkeypatch):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    incoming = temp_dir / "incoming"
    incoming.write_bytes(b"unrelated")
    real_open = approval.open_trusted_file

    def race_open(path, flags):
        os.replace(incoming, store_path)
        return real_open(path, flags)

    monkeypatch.setattr(approval, "open_trusted_file", race_open)
    with pytest.raises(approval.ApprovalStoreError) as captured:
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert isinstance(captured.value.__cause__, OSError)
    assert store_path.read_bytes() == b"unrelated"
    assert not list(temp_dir.glob(".approvals-*.tmp"))


@POSIX_ONLY
@pytest.mark.parametrize("replacement_kind", ["file", "symlink"])
def test_temp_replacement_during_write_is_not_published_or_deleted(
    temp_dir, monkeypatch, replacement_kind
):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    incoming = temp_dir / "incoming"
    sentinel = temp_dir / "unrelated"
    sentinel.write_bytes(b"unrelated")
    if replacement_kind == "symlink":
        _symlink(sentinel, incoming)
    else:
        incoming.write_bytes(b"unrelated")
    moved = temp_dir / "moved-owned-temp"
    real_fsync = os.fsync
    replaced_paths = []

    def replace_temp(descriptor):
        real_fsync(descriptor)
        [temporary] = temp_dir.glob(".approvals-*.tmp")
        temporary.rename(moved)
        incoming.rename(temporary)
        replaced_paths.append(temporary)

    monkeypatch.setattr(approval.os, "fsync", replace_temp)
    with pytest.raises(approval.ApprovalStoreError):
        approval._write_serialized_store(store_path, REPLACEMENT)
    assert store_path.read_bytes() == ORIGINAL
    assert replaced_paths[0].read_bytes() == b"unrelated"
    assert replaced_paths[0].is_symlink() == (replacement_kind == "symlink")
    assert moved.read_bytes() == REPLACEMENT
    assert sentinel.read_bytes() == b"unrelated"


def test_cleanup_failure_does_not_replace_publication_error(temp_dir, monkeypatch):
    store_path = temp_dir / "approvals.json"
    store_path.write_bytes(ORIGINAL)
    failure = OSError(errno.EIO, "publication failure")

    def fail_publish(*_args):
        raise failure

    def fail_cleanup(*_args):
        raise PermissionError(errno.EACCES, "cleanup failure")

    with monkeypatch.context() as patch:
        patch.setattr(approval.os, "replace", fail_publish)
        patch.setattr(Path, "unlink", fail_cleanup)
        with pytest.raises(approval.ApprovalStoreError) as captured:
            approval._write_serialized_store(store_path, REPLACEMENT)
    assert captured.value.__cause__ is failure
    assert store_path.read_bytes() == ORIGINAL
    [temporary] = temp_dir.glob(".approvals-*.tmp")
    assert temporary.read_bytes() == REPLACEMENT


def test_no_production_umask_calls():
    package = Path(approval.__file__).resolve().parents[1]
    for source in package.rglob("*.py"):
        assert "os.umask(" not in source.read_text(encoding="utf-8"), source
