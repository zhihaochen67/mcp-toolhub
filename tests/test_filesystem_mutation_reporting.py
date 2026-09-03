"""Exact-byte mutation results and the boundary at successful publication."""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.tools import filesystem


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _approve(root, operation, original=b"old\n", content="new\n"):
    target = root / "file.txt"
    if original is not None:
        target.write_bytes(original)
    expected_hash = _sha(original) if original is not None else None
    if operation == "write":
        pending = filesystem.write_file(target.name, content, expected_hash, root=root)
        resume = filesystem.write_file_approved
    else:
        old = original.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        patch = "".join(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"a/{target.name}",
                tofile=f"b/{target.name}",
            )
        )
        pending = filesystem.apply_patch(target.name, patch, expected_hash, root=root)
        resume = filesystem.apply_patch_approved
    assert pending.outcome == ContractOutcome.APPROVAL_REQUIRED
    approval.approve_request(pending.request_id)
    return target, pending, resume


def _assert_success_audit(done, operation):
    assert done.outcome == ContractOutcome.SUCCEEDED
    assert done.executed is True
    assert done.error is None
    assert done.approval_status == ApprovalStatus.CONSUMED
    event = audit.read_recent(limit=1)[-1]
    tool = "write_file_approved" if operation == "write" else "apply_patch_approved"
    assert event["tool"] == f"filesystem.{tool}"
    assert event["action"] == "execute_approved"
    assert event["executed"] is True
    assert event["success"] is True
    assert event["request_id"] == done.request_id
    assert event["trace_id"] == done.trace_id
    fields = {"path", "previous_hash", "new_hash"}
    fields |= (
        {"created", "bytes_written"}
        if operation == "write"
        else {"changed", "additions", "deletions", "bytes_before", "bytes_after"}
    )
    assert event["arguments"] == done.model_dump(include=fields)


@pytest.mark.parametrize("original", [None, b"old\r\n"])
@pytest.mark.parametrize("content", ["", "café 雪 \U0001f642\n", "a\r\nb\rc\n"])
def test_write_reports_exact_published_utf8_bytes(temp_dir, original, content):
    target, pending, resume = _approve(temp_dir, "write", original, content)

    done = resume(pending.request_id, root=temp_dir)

    published = target.read_bytes()
    assert published == content.encode("utf-8")
    assert done.bytes_written == len(published)
    assert done.new_hash == _sha(published)
    assert done.previous_hash == (_sha(original) if original is not None else None)
    assert done.created is (original is None)
    _assert_success_audit(done, "write")


@pytest.mark.parametrize("original", [b"old\n", b"old\r\n"])
def test_changed_patch_reports_exact_original_and_published_bytes(temp_dir, original):
    content = "café 雪 \U0001f642\n"
    target, pending, resume = _approve(temp_dir, "patch", original, content)

    done = resume(pending.request_id, root=temp_dir)

    published = target.read_bytes()
    assert published == content.encode("utf-8")
    assert done.changed is True
    assert done.bytes_before == len(original)
    assert done.bytes_after == len(published)
    assert done.previous_hash == _sha(original)
    assert done.new_hash == _sha(published)
    _assert_success_audit(done, "patch")


@pytest.mark.parametrize("original", [b"old\n", b"old\r\n", b"old\r"])
def test_unchanged_patch_preserves_exact_original_bytes(
    temp_dir, monkeypatch, original
):
    target = temp_dir / "file.txt"
    target.write_bytes(original)
    patch = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n old\n"
    pending = filesystem.apply_patch(target.name, patch, _sha(original), root=temp_dir)
    assert pending.outcome == ContractOutcome.APPROVAL_REQUIRED
    approval.approve_request(pending.request_id)

    def unexpected_publication(*_args):
        pytest.fail("An unchanged patch must not publish")

    monkeypatch.setattr(filesystem, "_atomic_write_text", unexpected_publication)
    done = filesystem.apply_patch_approved(pending.request_id, root=temp_dir)

    assert target.read_bytes() == original
    assert done.changed is False
    assert done.bytes_before == done.bytes_after == len(original)
    assert done.previous_hash == done.new_hash == _sha(original)
    _assert_success_audit(done, "patch")


@pytest.mark.parametrize("operation", ["write", "patch"])
@pytest.mark.parametrize(
    "after_publication", ["read-denied", "removed", "replaced", "modified"]
)
def test_published_mutation_stays_successful(
    temp_dir, monkeypatch, operation, after_publication
):
    original = b"old\r\n"
    content = "café 雪 \U0001f642\n"
    target, pending, resume = _approve(temp_dir, operation, original, content)
    atomic_write = filesystem._atomic_write_text
    path_open = Path.open
    published = []
    post_publication_reads = []

    def deny_target_read(path, mode="r", *args, **kwargs):
        if path == target and "r" in mode:
            post_publication_reads.append(path)
            raise PermissionError("injected post-publication read failure")
        return path_open(path, mode, *args, **kwargs)

    with monkeypatch.context() as mutation:

        def publish_then_change(path, text):
            atomic_write(path, text)
            published.append(target.read_bytes())
            if after_publication == "read-denied":
                mutation.setattr(Path, "open", deny_target_read)
            elif after_publication == "removed":
                target.unlink()
            elif after_publication == "replaced":
                replacement = temp_dir / "third-party.txt"
                replacement.write_bytes(b"third-party bytes")
                replacement.replace(target)
            else:
                target.write_bytes(b"third-party bytes")

        mutation.setattr(filesystem, "_atomic_write_text", publish_then_change)
        done = resume(pending.request_id, root=temp_dir)

    assert published == [content.encode("utf-8")]
    assert post_publication_reads == []
    assert done.previous_hash == _sha(original)
    assert done.new_hash == _sha(published[0])
    if operation == "write":
        assert done.bytes_written == len(published[0])
    else:
        assert done.changed is True
        assert done.bytes_after == len(published[0])
    _assert_success_audit(done, operation)
    if after_publication == "removed":
        assert not target.exists()
    else:
        assert target.read_bytes() == (
            published[0] if after_publication == "read-denied" else b"third-party bytes"
        )
    replay = resume(pending.request_id, root=temp_dir)
    assert replay.outcome == ContractOutcome.APPROVAL_CONSUMED
    assert replay.executed is False


@pytest.mark.parametrize("unchanged", [False, True])
def test_patch_reads_original_once_without_reopening_for_metadata(
    temp_dir, monkeypatch, unchanged
):
    target = temp_dir / "file.txt"
    original = b"old\r\n"
    target.write_bytes(original)
    body = " old\n" if unchanged else "-old\n+new\n"
    pending = filesystem.apply_patch(
        target.name,
        "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n" + body,
        _sha(original),
        root=temp_dir,
    )
    approval.approve_request(pending.request_id)
    path_open = Path.open
    reads = []

    def count_target_reads(path, mode="r", *args, **kwargs):
        if path == target and "r" in mode:
            reads.append(mode)
            assert len(reads) <= 2, "Only expected_hash validation and original read"
        return path_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", count_target_reads)
    done = filesystem.apply_patch_approved(pending.request_id, root=temp_dir)

    assert reads == ["rb", "rb"]
    assert done.previous_hash == _sha(original)
    assert done.new_hash == _sha(original if unchanged else b"new\n")
    _assert_success_audit(done, "patch")


@pytest.mark.parametrize("operation", ["write", "patch"])
@pytest.mark.parametrize("stage", ["metadata", "temporary-write", "publication"])
def test_prepublication_failure_is_unexecuted(temp_dir, monkeypatch, operation, stage):
    target, pending, resume = _approve(temp_dir, operation)

    def fail(*_args, **_kwargs):
        if stage == "metadata":
            raise ValueError("injected metadata preparation failure")
        raise OSError("injected publication preparation failure")

    if stage == "metadata":
        monkeypatch.setattr(filesystem, "_sha256_bytes", fail)
    elif stage == "temporary-write":
        monkeypatch.setattr(filesystem, "open", fail, raising=False)
    else:
        replace = filesystem.os.replace

        def fail_target_replace(source, destination):
            if Path(destination) == target:
                fail()
            return replace(source, destination)

        monkeypatch.setattr(filesystem.os, "replace", fail_target_replace)

    done = resume(pending.request_id, root=temp_dir)

    expected = ContractOutcome.FAILED
    error_code = f"FILE_{operation.upper()}_FAILED"
    if stage == "metadata":
        expected = (
            ContractOutcome.REFUSED
            if operation == "write"
            else ContractOutcome.CONFLICT
        )
        error_code = (
            "APPROVED_MUTATION_REFUSED" if operation == "write" else "MUTATION_CONFLICT"
        )
    assert done.outcome == expected
    assert done.error.code == error_code
    assert done.executed is False
    assert done.new_hash is None
    assert done.approval_status == ApprovalStatus.CONSUMED
    assert target.read_bytes() == b"old\n"
    assert not list(temp_dir.glob(".*.tmp"))
    event = audit.read_recent(limit=1)[-1]
    assert event["action"] == "failure"
    assert event["executed"] is False
    assert event["success"] is False
    assert event["request_id"] == done.request_id
    assert event["trace_id"] == done.trace_id


@pytest.mark.parametrize("operation", ["write", "patch"])
@pytest.mark.parametrize("stage", ["metadata", "temporary-write"])
@pytest.mark.parametrize("error_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_fatal_prepublication_exceptions_propagate(
    temp_dir, monkeypatch, operation, stage, error_type
):
    target, pending, resume = _approve(temp_dir, operation)
    error = error_type("injected fatal failure")

    def fail(*_args, **_kwargs):
        raise error

    if stage == "metadata":
        monkeypatch.setattr(filesystem, "_sha256_bytes", fail)
    else:
        monkeypatch.setattr(filesystem, "open", fail, raising=False)

    with pytest.raises(error_type) as raised:
        resume(pending.request_id, root=temp_dir)

    assert raised.value is error
    assert target.read_bytes() == b"old\n"
    assert not list(temp_dir.glob(".*.tmp"))
