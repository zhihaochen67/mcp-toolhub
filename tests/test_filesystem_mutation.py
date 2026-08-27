"""Tests for safe file mutation (write/patch), their approval flow, audit
integration, and the read_file SHA-256 enhancement."""

from __future__ import annotations

import difflib
import hashlib
import os
import secrets
import shutil
from pathlib import Path

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.paths import get_state_root
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.tools.filesystem import (
    MAX_PATCH_CHARS,
    MAX_WRITE_BYTES,
    MutationConflictError,
    apply_patch,
    apply_patch_approved,
    read_file,
    write_file,
    write_file_approved,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _put(root: Path, name: str, content: str) -> Path:
    """Write a file with byte-exact content (no newline translation)."""
    path = root / name
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)
    return path


def _make_patch(name, old, new, n=3):
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
            n=n,
        )
    )


def _last_event():
    events = audit.read_recent(limit=50)
    assert events
    return events[-1]


def _write_flow(root, path, content, expected_hash=None, create_parents=False):
    result = write_file(path, content, expected_hash, create_parents, root=root)
    approval.approve_request(result.request_id)
    return result, write_file_approved(result.request_id, root=root)


def _patch_flow(root, path, patch, expected_hash=None):
    result = apply_patch(path, patch, expected_hash, root=root)
    approval.approve_request(result.request_id)
    return result, apply_patch_approved(result.request_id, root=root)


# --------------------------------------------------------------------------
# READ
# --------------------------------------------------------------------------


def test_read_file_returns_sha256(temp_dir):
    data = "hello\nworld\n"
    _put(temp_dir, "a.txt", data)

    result = read_file("a.txt", root=temp_dir)

    assert result.path == "a.txt"
    assert result.size == len(data.encode("utf-8"))
    assert result.content == data
    assert result.sha256 == _sha(data)


# --------------------------------------------------------------------------
# WRITE
# --------------------------------------------------------------------------


def test_write_file_create_requires_approval_and_creates(temp_dir):
    result = write_file("a.txt", "hello world", root=temp_dir)

    assert result.executed is False
    assert result.approval_status == ApprovalStatus.PENDING
    assert result.request_id
    assert result.trace_id
    assert not (temp_dir / "a.txt").exists()

    approval.approve_request(result.request_id)
    done = write_file_approved(result.request_id, root=temp_dir)

    assert done.executed is True
    assert done.created is True
    assert done.bytes_written == len(b"hello world")
    assert done.previous_hash is None
    assert done.new_hash == _sha("hello world")
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "hello world"


def test_write_file_modifies_existing_file(temp_dir):
    _put(temp_dir, "a.txt", "old")

    result, done = _write_flow(temp_dir, "a.txt", "new")

    assert result.executed is False
    assert done.executed is True
    assert done.created is False
    assert done.previous_hash == _sha("old")
    assert done.new_hash == _sha("new")
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "new"


def test_write_file_create_parents_false_rejects_missing_parent(temp_dir):
    with pytest.raises(FileNotFoundError):
        write_file("missing/dir/a.txt", "x", root=temp_dir)


def test_write_file_create_parents_true_works(temp_dir):
    _result, done = _write_flow(temp_dir, "sub/dir/a.txt", "deep", create_parents=True)

    assert done.executed is True
    assert done.path == "sub/dir/a.txt"
    assert (temp_dir / "sub" / "dir" / "a.txt").read_text(encoding="utf-8") == "deep"


def test_write_file_traversal_rejected(temp_dir):
    with pytest.raises(ValueError, match="escapes"):
        write_file("../escape.txt", "x", root=temp_dir)

    assert not (temp_dir.parent / "escape.txt").exists()


def test_write_file_absolute_path_rejected(temp_dir):
    outside = temp_dir.parent / "outside.txt"

    with pytest.raises(ValueError, match="Absolute"):
        write_file(str(outside), "x", root=temp_dir)

    assert not outside.exists()


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:Windows\\win.ini",
        "\\\\server\\share\\file",
        "//server/share/file",
        "\\Windows\\win.ini",
    ],
)
def test_workspace_relative_paths_reject_foreign_root_syntax(temp_dir, path):
    with pytest.raises(ValueError, match="Absolute"):
        write_file(path, "x", root=temp_dir)

    with pytest.raises(ValueError, match="escapes workspace"):
        read_file(path, root=temp_dir)


def test_write_file_oversized_content_rejected(temp_dir):
    with pytest.raises(ValueError, match="too large"):
        write_file("a.txt", "x" * (MAX_WRITE_BYTES + 1), root=temp_dir)


def test_write_file_symlink_component_rejected(temp_dir, monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "link")

    with pytest.raises(ValueError, match="Symlinks are not allowed"):
        write_file("link/a.txt", "x", root=temp_dir)


def test_write_file_real_symlink_escape_rejected(temp_dir):
    outside = temp_dir.parent / f"outside-{secrets.token_hex(6)}"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = temp_dir / "link"

    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not supported in this environment: {exc}")

    try:
        with pytest.raises(ValueError, match="[Ss]ymlink"):
            write_file("link/secret.txt", "x", root=temp_dir)

        assert (outside / "secret.txt").read_text(encoding="utf-8") == "secret"
    finally:
        link.unlink()
        shutil.rmtree(outside, ignore_errors=True)


def test_write_file_expected_hash_match_succeeds(temp_dir):
    _put(temp_dir, "a.txt", "current")

    _result, done = _write_flow(
        temp_dir, "a.txt", "updated", expected_hash=_sha("current")
    )

    assert done.executed is True
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "updated"


def test_write_file_stale_expected_hash_conflict(temp_dir):
    _put(temp_dir, "a.txt", "current")

    with pytest.raises(MutationConflictError, match="Conflict"):
        write_file("a.txt", "updated", expected_hash=_sha("stale"), root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "current"


def test_write_file_approved_conflict_at_execution(temp_dir):
    _put(temp_dir, "a.txt", "current")

    result = write_file(
        "a.txt", "updated", expected_hash=_sha("current"), root=temp_dir
    )
    # The file changes between the request and the approval:
    _put(temp_dir, "a.txt", "tampered")
    approval.approve_request(result.request_id)

    with pytest.raises(MutationConflictError, match="Conflict"):
        write_file_approved(result.request_id, root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "tampered"


def test_write_atomic_no_temp_leftovers(temp_dir):
    _write_flow(temp_dir, "a.txt", "hello")

    leftovers = [p.name for p in temp_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


def test_write_failure_leaves_file_unchanged(temp_dir, monkeypatch):
    _put(temp_dir, "a.txt", "original")

    result = write_file("a.txt", "replacement", root=temp_dir)
    approval.approve_request(result.request_id)

    def boom(*args, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr("mcp_toolhub.tools.filesystem.open", boom, raising=False)

    with pytest.raises(OSError):
        write_file_approved(result.request_id, root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "original"
    leftovers = [p.name for p in temp_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []

    event = _last_event()
    assert event["action"] == "failure"
    assert event["error_type"] == "OSError"


# --------------------------------------------------------------------------
# PATCH
# --------------------------------------------------------------------------


def test_apply_patch_valid_patch_succeeds(temp_dir):
    old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
    new = "1\nTWO\n3\n4\n5\n6\n7\n8\nNINE\n10\n"
    _put(temp_dir, "a.txt", old)
    patch = _make_patch("a.txt", old, new, n=1)
    assert patch.count("@@ -") == 2  # two separate hunks

    result = apply_patch("a.txt", patch, root=temp_dir)
    assert result.executed is False

    approval.approve_request(result.request_id)
    done = apply_patch_approved(result.request_id, root=temp_dir)

    assert done.executed is True
    assert done.changed is True
    assert done.additions == 2
    assert done.deletions == 2
    assert done.previous_hash == _sha(old)
    assert done.new_hash == _sha(new)
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == new


def test_apply_patch_malformed_rejected(temp_dir):
    _put(temp_dir, "a.txt", "a\n")

    with pytest.raises(ValueError, match="[Mm]alformed"):
        apply_patch("a.txt", "this is not a patch", root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "a\n"


def test_apply_patch_redirect_to_other_file_rejected(temp_dir):
    _put(temp_dir, "a.txt", "a\n")
    patch = _make_patch("other.txt", "a\n", "b\n")

    with pytest.raises(ValueError, match="does not match target"):
        apply_patch("a.txt", patch, root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "a\n"


def test_apply_patch_escape_redirect_rejected(temp_dir):
    _put(temp_dir, "a.txt", "a\n")
    patch = "--- ../outside.txt\n+++ ../outside.txt\n@@ -1,1 +1,1 @@\n-a\n+b\n"

    with pytest.raises(ValueError, match="does not match target"):
        apply_patch("a.txt", patch, root=temp_dir)


def test_apply_patch_context_mismatch_rejected(temp_dir):
    _put(temp_dir, "a.txt", "line1\nline2\n")
    patch = _make_patch("a.txt", "different\ncontent\n", "different\ncontent2\n")

    result = apply_patch("a.txt", patch, root=temp_dir)  # structure is valid
    approval.approve_request(result.request_id)

    with pytest.raises(ValueError, match="does not match the file"):
        apply_patch_approved(result.request_id, root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "line1\nline2\n"


def test_apply_patch_requires_existing_file(temp_dir):
    patch = _make_patch("missing.txt", "a\n", "b\n")

    with pytest.raises(FileNotFoundError):
        apply_patch("missing.txt", patch, root=temp_dir)


def test_apply_patch_expected_hash_match_succeeds(temp_dir):
    _put(temp_dir, "a.txt", "one\ntwo\n")
    patch = _make_patch("a.txt", "one\ntwo\n", "one\nTWO\n")

    _result, done = _patch_flow(
        temp_dir, "a.txt", patch, expected_hash=_sha("one\ntwo\n")
    )

    assert done.executed is True
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "one\nTWO\n"


def test_apply_patch_stale_expected_hash_conflict(temp_dir):
    _put(temp_dir, "a.txt", "one\ntwo\n")
    patch = _make_patch("a.txt", "one\ntwo\n", "one\nTWO\n")

    with pytest.raises(MutationConflictError, match="Conflict"):
        apply_patch("a.txt", patch, expected_hash=_sha("stale"), root=temp_dir)

    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "one\ntwo\n"


def test_apply_patch_append_and_prepend(temp_dir):
    _put(temp_dir, "a.txt", "a\nb\n")
    _result, _ = _patch_flow(
        temp_dir, "a.txt", _make_patch("a.txt", "a\nb\n", "a\nb\nc\n")
    )
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "a\nb\nc\n"

    _put(temp_dir, "b.txt", "a\nb\n")
    _result2, _ = _patch_flow(
        temp_dir, "b.txt", _make_patch("b.txt", "a\nb\n", "z\na\nb\n")
    )
    assert (temp_dir / "b.txt").read_text(encoding="utf-8") == "z\na\nb\n"


def test_apply_patch_oversized_rejected(temp_dir):
    _put(temp_dir, "a.txt", "a\n")

    with pytest.raises(ValueError, match="too large"):
        apply_patch("a.txt", "x" * (MAX_PATCH_CHARS + 1), root=temp_dir)


def test_apply_patch_symlink_component_rejected(temp_dir, monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "link")
    patch = _make_patch("a.txt", "a\n", "b\n")

    with pytest.raises(ValueError, match="Symlinks are not allowed"):
        apply_patch("link/a.txt", patch, root=temp_dir)


def test_apply_patch_real_symlink_escape_rejected(temp_dir):
    outside = temp_dir.parent / f"outside-{secrets.token_hex(6)}"
    outside.mkdir()
    (outside / "secret.txt").write_text("a\n", encoding="utf-8")
    link = temp_dir / "link"

    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not supported in this environment: {exc}")

    try:
        patch = _make_patch("secret.txt", "a\n", "b\n")
        with pytest.raises(ValueError, match="[Ss]ymlink"):
            apply_patch("link/secret.txt", patch, root=temp_dir)

        assert (outside / "secret.txt").read_text(encoding="utf-8") == "a\n"
    finally:
        link.unlink()
        shutil.rmtree(outside, ignore_errors=True)


# --------------------------------------------------------------------------
# APPROVAL
# --------------------------------------------------------------------------


def test_mutations_create_pending_requests(temp_dir):
    _put(temp_dir, "a.txt", "x\n")

    write = write_file("b.txt", "y", root=temp_dir)
    patch = apply_patch("a.txt", _make_patch("a.txt", "x\n", "y\n"), root=temp_dir)

    for result in (write, patch):
        assert result.executed is False
        assert result.approval_status == ApprovalStatus.PENDING
        assert approval.get_request(result.request_id).status == ApprovalStatus.PENDING

    assert not (temp_dir / "b.txt").exists()
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "x\n"


def test_pending_cannot_execute(temp_dir):
    result = write_file("a.txt", "x", root=temp_dir)

    done = write_file_approved(result.request_id, root=temp_dir)

    assert done.executed is False
    assert done.approval_status == ApprovalStatus.PENDING
    assert not (temp_dir / "a.txt").exists()


def test_rejected_cannot_execute(temp_dir):
    result = write_file("a.txt", "x", root=temp_dir)
    approval.reject_request(result.request_id)

    done = write_file_approved(result.request_id, root=temp_dir)

    assert done.executed is False
    assert done.approval_status == ApprovalStatus.REJECTED
    assert not (temp_dir / "a.txt").exists()


def test_unknown_request_cannot_execute(temp_dir):
    done = write_file_approved("req_does_not_exist", root=temp_dir)

    assert done.executed is False
    assert done.approval_status is None


def test_approved_executes_exact_stored_mutation(temp_dir):
    result = write_file("target.txt", "exact-content", root=temp_dir)
    approval.approve_request(result.request_id)

    done = write_file_approved(result.request_id, root=temp_dir)

    assert done.executed is True
    assert (temp_dir / "target.txt").read_text(encoding="utf-8") == "exact-content"
    assert not (temp_dir / "other.txt").exists()


def test_approval_cannot_replay(temp_dir):
    result = write_file("a.txt", "first", root=temp_dir)
    approval.approve_request(result.request_id)

    first = write_file_approved(result.request_id, root=temp_dir)
    assert first.executed is True

    second = write_file_approved(result.request_id, root=temp_dir)
    assert second.executed is False
    assert second.approval_status == ApprovalStatus.CONSUMED
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "first"


@pytest.mark.parametrize(
    "workspace_case",
    ["missing", "none", "wrong-type", "empty", "relative", "mismatch"],
)
def test_write_approval_requires_strict_workspace_snapshot(
    temp_dir,
    workspace_case,
):
    payload = {
        "path": "blocked.txt",
        "content": "must not be written",
        "expected_hash": None,
        "create_parents": False,
    }
    workspace_values = {
        "none": None,
        "wrong-type": 123,
        "empty": "",
        "relative": ".",
        "mismatch": str(temp_dir.parent.resolve()),
    }
    if workspace_case != "missing":
        payload["workspace_root"] = workspace_values[workspace_case]

    request = approval.create_request(
        kind="file_write",
        risk=RiskLevel.MEDIUM,
        risk_reason="test",
        payload=payload,
    )
    approval.approve_request(request.request_id)

    with pytest.raises(ValueError, match="workspace"):
        write_file_approved(request.request_id, root=temp_dir)

    assert approval.get_request(request.request_id).status == ApprovalStatus.CONSUMED
    replay = write_file_approved(request.request_id, root=temp_dir)
    assert replay.executed is False
    assert replay.approval_status == ApprovalStatus.CONSUMED
    assert not (temp_dir / "blocked.txt").exists()


def test_expired_approval_blocks_execution(temp_dir, monkeypatch):
    from datetime import timedelta

    _put(temp_dir, "a.txt", "old")

    result = write_file("a.txt", "new", root=temp_dir)
    approval.approve_request(result.request_id)

    request = approval.get_request(result.request_id)
    future = request.expires_at + timedelta(seconds=5)
    monkeypatch.setattr("mcp_toolhub.security.approval._now", lambda: future)

    done = write_file_approved(result.request_id, root=temp_dir)

    assert done.executed is False
    assert done.approval_status == ApprovalStatus.EXPIRED
    assert (temp_dir / "a.txt").read_text(encoding="utf-8") == "old"


def test_filesystem_tool_schemas():
    import anyio
    from mcp.server import MCPServer

    from mcp_toolhub.tools.filesystem import register_filesystem_tools

    srv = MCPServer("test")
    register_filesystem_tools(srv)

    async def main():
        tools = {t.name: t for t in await srv.list_tools()}

        assert set(
            tools["filesystem.write_file"].input_schema.get("properties", {})
        ) == {"path", "content", "expected_hash", "create_parents"}
        assert set(
            tools["filesystem.apply_patch"].input_schema.get("properties", {})
        ) == {"path", "patch", "expected_hash"}
        assert set(
            tools["filesystem.write_file_approved"].input_schema.get("properties", {})
        ) == {"request_id"}
        assert set(
            tools["filesystem.apply_patch_approved"].input_schema.get("properties", {})
        ) == {"request_id"}

        assert tools["filesystem.read_file"].annotations.read_only_hint is True
        assert tools["filesystem.write_file"].annotations.read_only_hint is False
        assert tools["filesystem.write_file"].annotations.destructive_hint is True
        assert tools["filesystem.apply_patch"].annotations.destructive_hint is True

    anyio.run(main)


# --------------------------------------------------------------------------
# AUDIT
# --------------------------------------------------------------------------


def test_successful_mutation_audited(temp_dir):
    result, done = _write_flow(temp_dir, "a.txt", "hello")

    event = _last_event()
    assert event["tool"] == "filesystem.write_file_approved"
    assert event["action"] == "execute_approved"
    assert event["success"] is True
    assert event["executed"] is True
    assert event["request_id"] == result.request_id
    assert event["trace_id"] == done.trace_id
    assert event["arguments"]["path"] == "a.txt"
    assert event["arguments"]["created"] is True
    assert event["arguments"]["bytes_written"] == 5
    assert event["arguments"]["new_hash"] == _sha("hello")


def test_failed_mutation_audited(temp_dir):
    with pytest.raises(ValueError):
        write_file("../escape.txt", "x", root=temp_dir)

    event = _last_event()
    assert event["tool"] == "filesystem.write_file"
    assert event["action"] == "failure"
    assert event["success"] is False
    assert event["error_type"] == "ValueError"
    assert event["arguments"]["path"] == "../escape.txt"


def test_approval_lifecycle_audited(temp_dir):
    result = write_file("a.txt", "x", root=temp_dir)

    event = _last_event()
    assert event["tool"] == "filesystem.write_file"
    assert event["action"] == "approval_request"
    assert event["approval_status"] == "PENDING"
    assert event["request_id"] == result.request_id
    assert event["arguments"]["content_chars"] == 1


def test_audit_log_contains_no_content_or_patch(temp_dir):
    sentinel = "UNIQUE-SENTINEL-9f3c2e71-content"
    patch_sentinel = "UNIQUE-SENTINEL-88aa1b2c-patch"

    _write_flow(temp_dir, "a.txt", f"line1\n{sentinel}\nline3\n")

    _put(temp_dir, "b.txt", "x\ny\n")
    patch = _make_patch("b.txt", "x\ny\n", f"x\n{patch_sentinel}\ny\n")
    _patch_flow(temp_dir, "b.txt", patch)

    raw = (get_state_root() / "audit.jsonl").read_text(encoding="utf-8")
    assert sentinel not in raw
    assert patch_sentinel not in raw

    # The approval messages returned to the agent must not leak either.
    result = write_file("c.txt", f"zzz{sentinel}zzz", root=temp_dir)
    assert sentinel not in result.message
