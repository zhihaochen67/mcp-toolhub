"""Total-byte, race, and trusted-read regressions for audit compaction."""

from __future__ import annotations

import errno
import io
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_toolhub.observability import audit

LIMIT = 64 * 1024 * 1024
ROW = b'{"trace_id":"trc_boundary"}\n'
POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")


class _ObservedReader:
    def __init__(self, handle, before_read=None, after_read=None):
        assert isinstance(handle, io.FileIO), "source reads must not prefetch"
        self.handle = handle
        self.before_read = before_read
        self.after_read = after_read
        self.requests = []
        self.read_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.handle.close()

    def fileno(self):
        return self.handle.fileno()

    def seek(self, offset):
        return self.handle.seek(offset)

    def read(self, size):
        self.requests.append(size)
        if self.before_read is not None:
            self.before_read(self, size)
        data = self.handle.read(size)
        self.read_bytes += len(data)
        if self.after_read is not None:
            self.after_read(self, data)
        return data


def _observe_readers(patch, *, before_read=None, after_read=None):
    real_fdopen = os.fdopen
    readers = []

    def fdopen(descriptor, mode, *args, **kwargs):
        handle = real_fdopen(descriptor, mode, *args, **kwargs)
        if mode != "rb":
            return handle
        reader = _ObservedReader(handle, before_read, after_read)
        readers.append(reader)
        return reader

    patch.setattr(audit.os, "fdopen", fdopen)
    return readers


def _forbidden(*_args, **_kwargs):
    raise AssertionError("oversized input must not reach this operation")


def test_compaction_ceiling_is_independent_of_existing_limits():
    assert audit.MAX_COMPACTION_READ_BYTES == LIMIT
    assert audit.MAX_COMPACTION_LINE_BYTES == 1_000_000
    assert audit.MAX_COMPACTION_EVENTS == 100_000
    assert audit.MAX_READ_BYTES == 1_000_000
    assert audit.MAX_READ_EVENTS == 100


@pytest.mark.parametrize("apply", [False, True])
def test_exact_64_mib_is_accepted_without_reading_an_extra_byte(
    temp_dir, monkeypatch, apply
):
    path = temp_dir / "audit.jsonl"
    # Stream a real 64 MiB JSONL file using only a 64 KiB in-memory block.
    block = ROW[:-1] + b" " * (64 * 1024 - len(ROW)) + b"\n"
    with path.open("wb") as handle:
        for _ in range(1024):
            handle.write(block)
    assert path.stat().st_size == LIMIT

    with monkeypatch.context() as patch:
        readers = _observe_readers(patch)
        result = audit.compact_audit(2, apply=apply, audit_path=path)

    assert (result.total, result.retained, result.removed) == (1024, 2, 1022)
    assert result.changed is apply
    assert readers[0].read_bytes == LIMIT
    assert sum(readers[0].requests) == LIMIT  # No extra EOF probe.
    assert all(reader.handle.closed for reader in readers)
    if apply:
        assert path.read_bytes() == block * 2
        assert readers[1].read_bytes == len(block) * 2
    else:
        assert path.stat().st_size == LIMIT


@pytest.mark.parametrize("apply", [False, True])
def test_64_mib_plus_one_is_rejected_before_read_parse_or_publication(
    temp_dir, monkeypatch, apply
):
    path = temp_dir / "audit.jsonl"
    # The malformed prefix also proves size preflight wins over JSON parsing.
    with path.open("wb") as handle:
        handle.write(b"private malformed audit prefix")
        handle.truncate(LIMIT + 1)

    with monkeypatch.context() as patch:
        readers = _observe_readers(patch)
        patch.setattr(audit.json, "loads", _forbidden)
        patch.setattr(audit, "_write_compacted_audit", _forbidden)
        with pytest.raises(audit.AuditMaintenanceError, match="compaction read limit"):
            audit.compact_audit(1, apply=apply, audit_path=path)

    assert path.stat().st_size == LIMIT + 1
    with path.open("rb") as handle:
        assert handle.read(30) == b"private malformed audit prefix"
    assert readers[0].requests == []
    assert readers[0].handle.closed
    assert not list(temp_dir.glob(".audit-*.tmp"))


@pytest.mark.parametrize("timing", ["before_read", "after_eof"])
@pytest.mark.parametrize("apply", [False, True])
def test_growth_after_preflight_never_reads_past_budget_or_returns_partial_scan(
    temp_dir, monkeypatch, timing, apply
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(b"{}\n" * 2)
    grown = b"{}\n" * 9
    mutated = False

    def grow(reader, data_or_size):
        nonlocal mutated
        if not mutated and (timing == "before_read" or data_or_size == b""):
            path.write_bytes(grown)
            mutated = True
        assert reader.read_bytes <= 24

    with monkeypatch.context() as patch:
        patch.setattr(audit, "MAX_COMPACTION_READ_BYTES", 24)
        readers = _observe_readers(
            patch,
            before_read=grow if timing == "before_read" else None,
            after_read=grow if timing == "after_eof" else None,
        )
        patch.setattr(audit, "_write_compacted_audit", _forbidden)
        with pytest.raises(audit.AuditMaintenanceError, match="compaction read limit"):
            audit.compact_audit(1, apply=apply, audit_path=path)

    assert mutated
    assert readers[0].read_bytes == (24 if timing == "before_read" else 6)
    assert all(0 < size <= 24 for size in readers[0].requests)
    assert readers[0].handle.closed
    assert path.read_bytes() == grown
    assert not list(temp_dir.glob(".audit-*.tmp"))


@pytest.mark.parametrize("stale_final_size", [False, True])
def test_underreported_size_cannot_bypass_cumulative_read_accounting(
    temp_dir, monkeypatch, stale_final_size
):
    path = temp_dir / "audit.jsonl"
    original = b"{}\n" * 9
    path.write_bytes(original)
    real_fstat = os.fstat
    stat_calls = 0

    with monkeypatch.context() as patch:
        readers = _observe_readers(patch)

        def stale_size(descriptor):
            nonlocal stat_calls
            if readers and descriptor == readers[0].fileno():
                stat_calls += 1
                if stat_calls == 1 or stale_final_size:
                    return SimpleNamespace(st_size=0)
            return real_fstat(descriptor)

        patch.setattr(audit, "MAX_COMPACTION_READ_BYTES", 24)
        patch.setattr(audit.os, "fstat", stale_size)
        patch.setattr(audit, "_write_compacted_audit", _forbidden)
        with pytest.raises(audit.AuditMaintenanceError):
            audit.compact_audit(1, apply=True, audit_path=path)

    assert stat_calls == 2
    assert readers[0].requests == [24]
    assert readers[0].read_bytes == 24
    assert readers[0].handle.closed
    assert path.read_bytes() == original


@pytest.mark.parametrize("timing", ["before_copy", "during_copy"])
def test_growth_during_retained_suffix_read_cannot_publish_partial_compaction(
    temp_dir, monkeypatch, timing
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(b"{}\n" * 4)
    grown = b"{}\n" * 7
    real_writer = audit._write_compacted_audit

    with monkeypatch.context() as patch:
        patch.setattr(audit, "MAX_COMPACTION_READ_BYTES", 20)

        def grow_on_read(reader, _size):
            if timing == "during_copy" and len(readers) == 2:
                path.write_bytes(grown)

        readers = _observe_readers(patch, before_read=grow_on_read)

        def write(compaction_path, offset):
            assert offset == 9
            if timing == "before_copy":
                path.write_bytes(grown)
            real_writer(compaction_path, offset)

        patch.setattr(audit, "_write_compacted_audit", write)
        patch.setattr(audit.os, "replace", _forbidden)
        with pytest.raises(audit.AuditMaintenanceError, match="compaction read limit"):
            audit.compact_audit(1, apply=True, audit_path=path)

    assert path.read_bytes() == grown
    assert readers[1].read_bytes == (0 if timing == "before_copy" else 11)
    assert all(reader.handle.closed for reader in readers)
    assert not list(temp_dir.glob(".audit-*.tmp"))


@pytest.mark.parametrize("extra_byte", [False, True])
@pytest.mark.parametrize("terminated", [False, True])
def test_existing_line_size_and_incomplete_line_rules_are_unchanged(
    temp_dir, extra_byte, terminated
):
    path = temp_dir / "audit.jsonl"
    size = 1_000_000 + int(extra_byte)
    line = b"{}" + b" " * (size - 2 - int(terminated))
    if terminated:
        line += b"\n"
    path.write_bytes(line)

    if terminated and not extra_byte:
        result = audit.compact_audit(1, apply=True, audit_path=path)
        assert result.total == result.retained == 1
        assert result.changed is False
    else:
        with pytest.raises(audit.AuditMaintenanceError, match="incomplete"):
            audit.compact_audit(1, apply=True, audit_path=path)
    assert path.read_bytes() == line


@pytest.mark.parametrize("apply", [False, True])
def test_path_exists_is_not_compaction_open_authority(temp_dir, monkeypatch, apply):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ROW)
    real_exists = Path.exists

    def exists(candidate):
        if candidate == path:
            raise AssertionError("trusted open must decide whether the log exists")
        return real_exists(candidate)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", exists)
        result = audit.compact_audit(1, apply=apply, audit_path=path)
    assert result.total == result.retained == 1


def test_missing_trusted_open_is_a_noop(temp_dir, monkeypatch):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ROW)

    def missing(*_args):
        raise FileNotFoundError(errno.ENOENT, "gone before open")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "open_trusted_file", missing)
        result = audit.compact_audit(1, audit_path=path)
    assert result.total == result.retained == result.removed == 0
    assert result.changed is False
    assert path.read_bytes() == ROW


@pytest.mark.parametrize("stage", ["open", "stat", "read"])
@pytest.mark.parametrize(
    "error_type", [PermissionError, MemoryError, KeyboardInterrupt, SystemExit]
)
def test_read_failure_mapping_preserves_causes_interrupts_and_existing_bytes(
    temp_dir, monkeypatch, stage, error_type
):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ROW * 2)
    failure = error_type("private failure detail")

    def fail(*_args):
        raise failure

    with monkeypatch.context() as patch:
        readers = _observe_readers(patch, before_read=fail if stage == "read" else None)
        if stage == "open":
            patch.setattr(audit, "open_trusted_file", fail)
        elif stage == "stat":
            real_fstat = os.fstat

            def fail_stat(descriptor):
                if readers:
                    fail()
                return real_fstat(descriptor)

            patch.setattr(audit.os, "fstat", fail_stat)
        expected = (
            audit.AuditMaintenanceError if error_type is PermissionError else error_type
        )
        with pytest.raises(expected) as captured:
            audit.compact_audit(1, audit_path=path)

    if error_type is PermissionError:
        assert captured.value.__cause__ is failure
        assert str(captured.value) == "Audit log could not be read safely."
    else:
        assert captured.value is failure
    assert all(reader.handle.closed for reader in readers)
    assert path.read_bytes() == ROW * 2


def test_file_not_found_during_read_is_not_a_missing_log_noop(temp_dir, monkeypatch):
    path = temp_dir / "audit.jsonl"
    path.write_bytes(ROW)
    failure = FileNotFoundError(errno.ENOENT, "read failure after open")

    def fail(*_args):
        raise failure

    with monkeypatch.context() as patch:
        readers = _observe_readers(patch, before_read=fail)
        with pytest.raises(audit.AuditMaintenanceError) as captured:
            audit.compact_audit(1, audit_path=path)
    assert captured.value.__cause__ is failure
    assert readers[0].handle.closed
    assert path.read_bytes() == ROW


@POSIX_ONLY
@pytest.mark.parametrize("fallback", [False, True])
def test_compaction_rejects_symlink_without_changing_target_permissions(
    temp_dir, monkeypatch, fallback
):
    target = temp_dir / "target.jsonl"
    path = temp_dir / "audit.jsonl"
    target.write_bytes(ROW * 2)
    os.chmod(target, 0o644)
    path.symlink_to(target)

    with monkeypatch.context() as patch:
        if fallback:
            patch.setattr(audit.os, "O_NOFOLLOW", 0, raising=False)
        with pytest.raises(
            audit.AuditMaintenanceError, match="read safely"
        ) as captured:
            audit.compact_audit(1, apply=True, audit_path=path)
    assert isinstance(captured.value.__cause__, OSError)
    assert path.is_symlink()
    assert target.read_bytes() == ROW * 2
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
