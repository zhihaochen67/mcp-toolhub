"""Filesystem tools: read-only inspection plus approval-gated safe mutations.

Security model
--------------
* Read-only tools stay unchanged in behavior (``read_file`` additionally
  returns a SHA-256 of the exact file bytes).
* ``write_file`` / ``apply_patch`` are MEDIUM-risk mutations: they never
  write anything themselves. They validate the request, snapshot the exact
  intended mutation (path, content/patch, expected_hash, create_parents)
  into a PENDING approval request, and the trusted admin approves it
  out-of-band. The ``*_approved`` counterparts consume the single-use
  approval and execute *only* the stored snapshot — the caller cannot
  substitute a different path/content/patch.
* Paths are workspace-relative, resolved canonically, and must stay inside
  the workspace; absolute paths, escapes, and symlink components are
  rejected for mutations.
* Writes are atomic: a unique temp file in the same directory is written,
  fsync'd, and ``os.replace``d over the target.
* Optimistic concurrency: an optional ``expected_hash`` must match the
  current SHA-256 of the target, otherwise the mutation is rejected with a
  conflict and the file is left untouched.
* Patches are narrowly-scoped unified diffs parsed and applied in-process:
  the header must name exactly the target file, no other file can be
  addressed, malformed or non-matching patches are rejected without any
  partial application.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from mcp_toolhub.contracts import (
    ContractError,
    ContractLifecycle,
    ContractOutcome,
    make_contract_error,
    outcome_for_approval_status,
)
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalRequest, ApprovalStatus
from mcp_toolhub.security.paths import (
    MAX_FILE_SIZE,
    get_workspace_root,
    is_portably_rooted_path,
    resolve_path_within,
    validate_workspace_snapshot,
)
from mcp_toolhub.security.risk import RiskLevel

MAX_WRITE_BYTES = 256 * 1024  # 256 KB of UTF-8 text
MAX_PATCH_CHARS = 256 * 1024
MAX_DIRECTORY_ENTRIES = 2_048

WRITE_RISK_REASON = "File mutation (write) requires approval."
PATCH_RISK_REASON = "File mutation (patch) requires approval."


class MutationConflictError(ValueError):
    """Optimistic-concurrency conflict: the file changed since it was read."""


class ReadFileResult(BaseModel):
    path: str
    size: int
    sha256: str
    content: str


class DirectoryEntry(BaseModel):
    name: str
    kind: Literal["file", "directory", "symlink", "other"]
    size: int | None = None


class ListDirectoryResult(BaseModel):
    path: str
    entries: list[DirectoryEntry]


class WriteFileResult(ContractLifecycle):
    path: str
    executed: bool
    created: bool = False
    bytes_written: int = 0
    previous_hash: str | None = None
    new_hash: str | None = None
    request_id: str | None = None
    approval_status: ApprovalStatus | None = None
    message: str = ""


class ApplyPatchResult(ContractLifecycle):
    path: str
    executed: bool
    changed: bool = False
    additions: int = 0
    deletions: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    previous_hash: str | None = None
    new_hash: str | None = None
    request_id: str | None = None
    approval_status: ApprovalStatus | None = None
    message: str = ""


READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)

MUTATION_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    open_world_hint=False,
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                raise ValueError(f"File too large (maximum {MAX_FILE_SIZE} bytes)")
            digest.update(chunk)
    return digest.hexdigest()


def _effective_root(root: Path | None) -> Path:
    return (root or get_workspace_root()).resolve()


def _relative_to_root(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    if str(relative) == ".":
        return "."
    return relative.as_posix()


def _ensure_no_symlink_components(root: Path, path: str) -> None:
    """Reject paths that traverse a symlink component, even one that points
    inside the workspace, for mutations."""
    candidate = Path(path)

    if is_portably_rooted_path(path):
        raise ValueError(f"Absolute paths are not allowed: {path}")

    current = root

    for part in candidate.parts:
        if part in ("", "."):
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise ValueError(f"Symlinks are not allowed: {path}")
        except OSError as exc:
            raise ValueError("Workspace path could not be inspected safely") from exc


def _resolve_mutation_target(root: Path, path: str) -> Path:
    """Resolve a mutation target with containment + no-symlink guarantees."""
    _ensure_no_symlink_components(root, path)

    target = resolve_path_within(path, root)

    if target.exists() and target.is_dir():
        raise ValueError(f"Path is a directory, not a file: {path}")
    if target.exists() and not target.is_file():
        raise ValueError("Mutation target must be a regular file")

    return target


def _check_expected_hash(path: str, target: Path, expected_hash: str | None) -> None:
    """Optimistic concurrency: the current file must match expected_hash."""
    if expected_hash is None:
        return

    if not target.exists():
        raise MutationConflictError(
            f"Conflict: {path} does not exist (expected sha256 {expected_hash})"
        )

    try:
        actual = _sha256_file(target)
    except OSError as exc:
        raise MutationConflictError(
            f"Conflict: {path} could not be read for hash validation"
        ) from exc

    if actual != expected_hash:
        raise MutationConflictError(
            f"Conflict: {path} content changed "
            f"(expected sha256 {expected_hash}, actual {actual})"
        )


def _ensure_bounded_existing_file(path: str, target: Path) -> None:
    """Reject an existing mutation target above the workspace file bound."""

    try:
        oversized = target.exists() and target.stat().st_size > MAX_FILE_SIZE
    except OSError as exc:
        raise ValueError("Workspace file could not be inspected safely") from exc
    if oversized:
        raise ValueError(f"File too large (maximum {MAX_FILE_SIZE} bytes): {path}")


def _read_bounded_file_bytes(path: str, target: Path) -> bytes:
    """Read one file with a hard byte limit even if it changes after stat."""

    try:
        with target.open("rb") as handle:
            data = handle.read(MAX_FILE_SIZE + 1)
    except OSError as exc:
        raise ValueError(f"Workspace file could not be read: {path}") from exc

    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"File too large (maximum {MAX_FILE_SIZE} bytes): {path}")
    return data


def _decode_utf8_text(path: str, data: bytes) -> str:
    """Decode with the universal-newline behavior of ``Path.read_text``."""

    try:
        return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"File is not valid UTF-8 text: {path}") from exc


def _atomic_write_text(target: Path, text: str) -> None:
    """Atomically replace ``target``: temp file in the same directory,
    fsync, then ``os.replace``. Never leaves a partial file behind."""
    tmp_path = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"

    try:
        with open(tmp_path, "x", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, target)

    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# Unified-diff parsing / application (strict, single-file, in-process)
# --------------------------------------------------------------------------

_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class _PatchHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    old_lines: list[str]
    new_lines: list[str]
    added: int
    removed: int


def _strip_eol(line: str) -> str:
    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith("\n"):
        return line[:-1]
    return line


def _patch_header_name(line: str, marker: str) -> str:
    rest = _strip_eol(line[len(marker) :])
    return rest.split("\t", 1)[0]


def _normalize_patch_name(name: str) -> str:
    name = name.replace("\\", "/")
    for prefix in ("a/", "b/"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def parse_unified_patch(patch: str, target: str) -> list[_PatchHunk]:
    """Parse a single-file unified diff and validate it targets ``target``.

    Raises ``ValueError`` on anything malformed, ambiguous, out-of-order, or
    addressed to a different path. Never touches the filesystem.
    """
    raw_lines = patch.splitlines(keepends=True)

    if not raw_lines:
        raise ValueError("Malformed patch: patch is empty")

    index = 0

    if not raw_lines[index].startswith("--- "):
        raise ValueError("Malformed patch: missing '---' header")
    old_name = _patch_header_name(raw_lines[index], "--- ")
    index += 1

    if index >= len(raw_lines) or not raw_lines[index].startswith("+++ "):
        raise ValueError("Malformed patch: missing '+++' header")
    new_name = _patch_header_name(raw_lines[index], "+++ ")
    index += 1

    expected = _normalize_patch_name(target)

    for name in (old_name, new_name):
        if _normalize_patch_name(name) != expected:
            raise ValueError(
                f"Malformed patch: header path {name!r} "
                f"does not match target {target!r}"
            )

    hunks: list[_PatchHunk] = []

    while index < len(raw_lines):
        header_match = _HUNK_HEADER_RE.match(_strip_eol(raw_lines[index]))

        if not header_match:
            raise ValueError(
                "Malformed patch: expected hunk header, got: "
                f"{_strip_eol(raw_lines[index])[:60]!r}"
            )

        old_start = int(header_match.group(1))
        old_count = int(header_match.group(2) or 1)
        new_start = int(header_match.group(3))
        new_count = int(header_match.group(4) or 1)
        index += 1

        old_lines: list[str] = []
        new_lines: list[str] = []
        added = 0
        removed = 0
        last_kind: str | None = None

        while index < len(raw_lines) and not _HUNK_HEADER_RE.match(
            _strip_eol(raw_lines[index])
        ):
            line = raw_lines[index]

            if line.startswith(" "):
                text = line[1:]
                old_lines.append(text)
                new_lines.append(text)
                last_kind = " "
            elif line.startswith("-"):
                text = line[1:]
                old_lines.append(text)
                removed += 1
                last_kind = "-"
            elif line.startswith("+"):
                text = line[1:]
                new_lines.append(text)
                added += 1
                last_kind = "+"
            elif line.startswith("\\"):
                if last_kind is None:
                    raise ValueError(
                        "Malformed patch: 'no newline' marker without a preceding line"
                    )
                if last_kind in (" ", "-") and old_lines:
                    old_lines[-1] = _strip_eol(old_lines[-1])
                if last_kind in (" ", "+") and new_lines:
                    new_lines[-1] = _strip_eol(new_lines[-1])
            else:
                raise ValueError(
                    "Malformed patch: unexpected content line: "
                    f"{_strip_eol(line)[:60]!r}"
                )

            index += 1

        if old_count > 0 and len(old_lines) != old_count:
            raise ValueError(
                f"Malformed patch: hunk declares {old_count} old lines "
                f"but has {len(old_lines)}"
            )
        if new_count > 0 and len(new_lines) != new_count:
            raise ValueError(
                f"Malformed patch: hunk declares {new_count} new lines "
                f"but has {len(new_lines)}"
            )
        if old_count == 0 and old_lines:
            raise ValueError("Malformed patch: zero-count hunk contains old lines")
        if new_count == 0 and new_lines:
            raise ValueError("Malformed patch: zero-count hunk contains new lines")

        hunks.append(
            _PatchHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                old_lines=old_lines,
                new_lines=new_lines,
                added=added,
                removed=removed,
            )
        )

    if not hunks:
        raise ValueError("Malformed patch: no hunks")

    previous_end = 0
    for hunk in hunks:
        if hunk.old_start < previous_end:
            raise ValueError("Malformed patch: hunks overlap or are out of order")
        previous_end = hunk.old_start + hunk.old_count

    return hunks


def apply_patch_text(original: str, patch: str, target: str) -> tuple[str, int, int]:
    """Apply a single-file unified diff to ``original``.

    All hunks must match exactly; otherwise ``ValueError`` is raised and
    nothing is returned/partial. Returns ``(new_text, additions, deletions)``.
    """
    hunks = parse_unified_patch(patch, target)

    lines = original.splitlines(keepends=True)
    offset = 0
    added_total = 0
    removed_total = 0

    for hunk in hunks:
        start = hunk.old_start - 1 + offset

        if hunk.old_count == 0:
            if start < 0 or start > len(lines):
                raise ValueError("Patch hunk position is out of range")
        else:
            end = start + len(hunk.old_lines)
            if start < 0 or end > len(lines):
                raise ValueError("Patch hunk position is out of range")
            if lines[start:end] != hunk.old_lines:
                raise ValueError(
                    "Patch does not match the file content (stale or wrong file?)"
                )

        lines = (
            lines[:start] + list(hunk.new_lines) + lines[start + len(hunk.old_lines) :]
        )

        offset += len(hunk.new_lines) - len(hunk.old_lines)
        added_total += hunk.added
        removed_total += hunk.removed

    return "".join(lines), added_total, removed_total


# --------------------------------------------------------------------------
# Approval plumbing shared by the mutation tools
# --------------------------------------------------------------------------


def _load_and_consume(
    request_id: str,
) -> tuple[ApprovalRequest | None, ApprovalStatus | None, bool]:
    """Fetch and single-use-consume an APPROVED request.

    Returns ``(request, status, ok)`` where ``ok`` is True only when this
    call just atomically transitioned the request from APPROVED to CONSUMED.
    Unknown, PENDING, REJECTED, EXPIRED, and already-CONSUMED requests come
    back with ``ok=False`` and must never execute.
    """
    request = approval.get_request(request_id)

    if request is None:
        return None, None, False

    if request.status != ApprovalStatus.APPROVED:
        return request, request.status, False

    consumed = approval.consume_request(request_id)

    if consumed is None:
        current = approval.get_request(request_id)
        authoritative = current or request.model_copy(
            update={"status": ApprovalStatus.EXPIRED}
        )
        return authoritative, authoritative.status, False

    return consumed, consumed.status, True


def _payload_trace_id(request: ApprovalRequest | None) -> str | None:
    if request is None:
        return None
    return request.trace_id


def _approval_failure_contract(
    status: ApprovalStatus | None,
    message: str,
) -> tuple[ContractOutcome, ContractError]:
    if status is None:
        return (
            ContractOutcome.REFUSED,
            make_contract_error(
                "REQUEST_NOT_FOUND", "Approval request is unavailable."
            ),
        )
    return (
        outcome_for_approval_status(status),
        make_contract_error(
            f"APPROVAL_{status.value}",
            message,
            retryable=status == ApprovalStatus.PENDING,
        ),
    )


def _validate_payload(request: ApprovalRequest, kind: str, required: set[str]) -> dict:
    if request.kind != kind:
        raise ValueError(
            f"Approval request kind mismatch: expected {kind!r}, got {request.kind!r}"
        )

    payload = dict(request.payload or {})

    missing = sorted(key for key in required if key not in payload)
    if missing:
        raise ValueError(
            f"Approval request payload is missing keys: {', '.join(missing)}"
        )

    return payload


# --------------------------------------------------------------------------
# Read tool
# --------------------------------------------------------------------------


def read_file(path: str, root: Path | None = None) -> ReadFileResult:
    """Read a UTF-8 text file inside the workspace and return its SHA-256."""
    root = _effective_root(root)
    target = resolve_path_within(path, root)

    if not target.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not target.is_file():
        raise ValueError(f"Not a file: {path}")

    data = _read_bounded_file_bytes(path, target)
    content = _decode_utf8_text(path, data)

    return ReadFileResult(
        path=_relative_to_root(root, target),
        size=len(data),
        sha256=_sha256_bytes(data),
        content=content,
    )


def _list_directory(path: str = ".", root: Path | None = None) -> ListDirectoryResult:
    """Return one bounded, non-recursive workspace directory listing."""

    root = _effective_root(root)
    target = resolve_path_within(path, root)

    if not target.exists():
        raise FileNotFoundError(f"Directory not found: {path}")
    if not target.is_dir():
        raise ValueError(f"Not a directory: {path}")

    entries: list[DirectoryEntry] = []
    try:
        with os.scandir(target) as iterator:
            for item in iterator:
                if len(entries) >= MAX_DIRECTORY_ENTRIES:
                    raise ValueError(
                        "Directory contains too many entries "
                        f"(maximum {MAX_DIRECTORY_ENTRIES})"
                    )

                if item.is_symlink():
                    kind = "symlink"
                    size = None
                elif item.is_dir(follow_symlinks=False):
                    kind = "directory"
                    size = None
                elif item.is_file(follow_symlinks=False):
                    kind = "file"
                    size = item.stat(follow_symlinks=False).st_size
                else:
                    kind = "other"
                    size = None

                entries.append(
                    DirectoryEntry(
                        name=item.name,
                        kind=kind,
                        size=size,
                    )
                )
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"Workspace directory could not be read: {path}") from exc

    entries.sort(key=lambda item: item.name.lower())
    return ListDirectoryResult(
        path=_relative_to_root(root, target),
        entries=entries,
    )


# --------------------------------------------------------------------------
# Mutation tools (approval-gated)
# --------------------------------------------------------------------------


def _validate_write_input(
    path: str,
    content: str,
    expected_hash: str | None,
    create_parents: bool,
    root: Path,
) -> Path:
    if not isinstance(content, str):
        raise TypeError("Content must be a string")

    encoded = content.encode("utf-8")
    maximum_write = min(MAX_WRITE_BYTES, MAX_FILE_SIZE)
    if len(encoded) > maximum_write:
        raise ValueError(
            f"Content too large: {len(encoded)} bytes (maximum {maximum_write})"
        )

    target = _resolve_mutation_target(root, path)

    if not create_parents and not target.parent.is_dir():
        raise FileNotFoundError(f"Parent directory does not exist: {path}")

    _ensure_bounded_existing_file(path, target)
    _check_expected_hash(path, target, expected_hash)

    return target


def write_file(
    path: str,
    content: str,
    expected_hash: str | None = None,
    create_parents: bool = False,
    root: Path | None = None,
) -> WriteFileResult:
    """Create a PENDING approval request for a bounded UTF-8 text write.

    Never writes anything itself: the exact snapshot (path, content,
    expected_hash, create_parents) is stored in the approval request and is
    applied only via ``write_file_approved`` after out-of-band approval.
    """
    trace_id = audit.new_trace_id()
    started = time.monotonic()
    root = _effective_root(root)
    arguments = {
        "path": path,
        "content_chars": len(content) if isinstance(content, str) else None,
        "expected_hash": expected_hash,
        "create_parents": create_parents,
    }

    try:
        _validate_write_input(path, content, expected_hash, create_parents, root)
    except (FileNotFoundError, TypeError, ValueError) as exc:
        audit.record_event(
            trace_id=trace_id,
            tool="filesystem.write_file",
            action="failure",
            risk=RiskLevel.MEDIUM,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments=arguments,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        if isinstance(exc, MutationConflictError):
            return WriteFileResult(
                outcome=ContractOutcome.CONFLICT,
                trace_id=trace_id,
                error=make_contract_error("MUTATION_CONFLICT", str(exc)),
                path=path,
                executed=False,
                message=str(exc),
            )
        return WriteFileResult(
            outcome=ContractOutcome.REFUSED,
            trace_id=trace_id,
            error=make_contract_error(
                "MUTATION_REFUSED",
                "File write request was refused by validation.",
            ),
            path=path,
            executed=False,
            message=str(exc),
        )

    try:
        request = approval.create_request(
            kind="file_write",
            payload={
                "path": path,
                "content": content,
                "expected_hash": expected_hash,
                "create_parents": create_parents,
                "workspace_root": str(root),
            },
            risk=RiskLevel.MEDIUM,
            risk_reason=WRITE_RISK_REASON,
            trace_id=trace_id,
        )
    except approval.ApprovalStoreCapacityError as exc:
        message = str(exc)
        audit.record_event(
            trace_id=trace_id,
            tool="filesystem.write_file",
            action="approval_request_refused",
            risk=RiskLevel.MEDIUM,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"request_kind": "file_write"},
            error=message,
            error_type=type(exc).__name__,
        )
        return WriteFileResult(
            outcome=ContractOutcome.FAILED,
            trace_id=trace_id,
            error=make_contract_error("APPROVAL_STORE_CAPACITY", message),
            path=path,
            executed=False,
            message=message,
        )

    audit.record_event(
        trace_id=trace_id,
        tool="filesystem.write_file",
        action="approval_request",
        risk=RiskLevel.MEDIUM,
        approval_status=request.status,
        request_id=request.request_id,
        executed=False,
        success=True,
        duration_ms=_elapsed_ms(started),
        arguments=arguments,
    )

    return WriteFileResult(
        outcome=ContractOutcome.APPROVAL_REQUIRED,
        trace_id=trace_id,
        approval=request.public_handle(),
        path=path,
        executed=False,
        request_id=request.request_id,
        approval_status=request.status,
        message=(
            f"Approval required ({request.status.value}). "
            f"A trusted administrator must approve request "
            f"{request.request_id} before it can be applied."
        ),
    )


def write_file_approved(request_id: str, root: Path | None = None) -> WriteFileResult:
    """Execute exactly the mutation stored in an APPROVED request.

    Single-use: the approval is consumed atomically. The path, content,
    expected_hash and create_parents flag come from the stored snapshot only
    — no replacement values are accepted.
    """
    tool = "filesystem.write_file_approved"
    root = _effective_root(root)
    request, status, consumed_ok = _load_and_consume(request_id)
    trace_id = _payload_trace_id(request)
    lifecycle_trace_id = trace_id or audit.new_trace_id()
    started = time.monotonic()

    if not consumed_ok:
        path = (
            str((request.payload or {}).get("path", "")) if request is not None else ""
        )
        status_value = status.value if status else "unknown"
        audit.record_event(
            trace_id=lifecycle_trace_id,
            tool=tool,
            action="approval_rejected",
            approval_status=status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"request_id": request_id, "path": path or None},
            error=f"Request is {status_value}; cannot execute.",
            error_type="KeyError" if status is None else "ApprovalStateError",
        )
        outcome, error = _approval_failure_contract(
            status, f"Request is {status_value}; cannot execute."
        )
        return WriteFileResult(
            outcome=outcome,
            trace_id=lifecycle_trace_id,
            approval=(request.public_handle() if request is not None else None),
            error=error,
            path=path,
            executed=False,
            request_id=request_id,
            approval_status=status,
            message=f"Request is {status_value}; cannot execute.",
        )

    try:
        payload = _validate_payload(
            request,
            "file_write",
            {"path", "content", "expected_hash", "create_parents"},
        )
        validate_workspace_snapshot(payload, root)
        path = payload["path"]
        content = payload["content"]
        expected_hash = payload.get("expected_hash")
        create_parents = payload.get("create_parents", False)
        if not isinstance(path, str) or not isinstance(create_parents, bool):
            raise TypeError("Approval file write snapshot is malformed")

        target = _validate_write_input(
            path, content, expected_hash, create_parents, root
        )

        previous_hash = _sha256_file(target) if target.exists() else None
        created = not target.exists()

        if create_parents:
            target.parent.mkdir(parents=True, exist_ok=True)

        _atomic_write_text(target, content)

        new_hash = _sha256_file(target)
        bytes_written = len(content.encode("utf-8"))

    except (FileNotFoundError, TypeError, ValueError, OSError) as exc:
        audit.record_event(
            trace_id=lifecycle_trace_id,
            tool=tool,
            action="failure",
            risk=RiskLevel.MEDIUM,
            approval_status=request.status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={
                "path": str(request.payload.get("path", "")),
                "expected_hash": request.payload.get("expected_hash"),
            },
            error=str(exc),
            error_type=type(exc).__name__,
        )
        if isinstance(exc, MutationConflictError):
            outcome = ContractOutcome.CONFLICT
            error = make_contract_error("MUTATION_CONFLICT", str(exc))
        elif isinstance(exc, OSError):
            outcome = ContractOutcome.FAILED
            error = make_contract_error(
                "FILE_WRITE_FAILED",
                "Approved file write failed.",
            )
        else:
            outcome = ContractOutcome.REFUSED
            error = make_contract_error(
                "APPROVED_MUTATION_REFUSED",
                "Approved file write no longer satisfies its protected snapshot.",
            )
        return WriteFileResult(
            outcome=outcome,
            trace_id=lifecycle_trace_id,
            approval=request.public_handle(),
            error=error,
            path=str(request.payload.get("path", "")),
            executed=False,
            request_id=request_id,
            approval_status=request.status,
            message=error.message,
        )

    audit.record_event(
        trace_id=lifecycle_trace_id,
        tool=tool,
        action="execute_approved",
        risk=RiskLevel.MEDIUM,
        approval_status=request.status,
        request_id=request_id,
        executed=True,
        success=True,
        duration_ms=_elapsed_ms(started),
        arguments={
            "path": path,
            "created": created,
            "bytes_written": bytes_written,
            "previous_hash": previous_hash,
            "new_hash": new_hash,
        },
    )

    return WriteFileResult(
        outcome=ContractOutcome.SUCCEEDED,
        trace_id=lifecycle_trace_id,
        approval=request.public_handle(),
        path=path,
        executed=True,
        created=created,
        bytes_written=bytes_written,
        previous_hash=previous_hash,
        new_hash=new_hash,
        request_id=request_id,
        approval_status=request.status,
    )


def _validate_patch_input(
    path: str,
    patch: str,
    expected_hash: str | None,
    root: Path,
) -> Path:
    if not isinstance(patch, str):
        raise TypeError("Patch must be a string")

    if len(patch) > MAX_PATCH_CHARS:
        raise ValueError(
            f"Patch too large: {len(patch)} characters (maximum {MAX_PATCH_CHARS})"
        )

    target = _resolve_mutation_target(root, path)

    if target.exists():
        _ensure_bounded_existing_file(path, target)

    _check_expected_hash(path, target, expected_hash)

    if not target.exists():
        raise FileNotFoundError(f"File not found: {path}")
    # Structural validation: malformed patches and header redirections are
    # rejected before any approval request is created.
    parse_unified_patch(patch, path)

    return target


def apply_patch(
    path: str,
    patch: str,
    expected_hash: str | None = None,
    root: Path | None = None,
) -> ApplyPatchResult:
    """Create a PENDING approval request for a narrowly-scoped unified diff.

    Never modifies anything itself: the exact snapshot (path, patch,
    expected_hash) is stored in the approval request and applied only via
    ``apply_patch_approved`` after out-of-band approval.
    """
    trace_id = audit.new_trace_id()
    started = time.monotonic()
    root = _effective_root(root)
    arguments = {
        "path": path,
        "patch_chars": len(patch) if isinstance(patch, str) else None,
        "patch_sha256": (
            _sha256_bytes(patch.encode("utf-8")) if isinstance(patch, str) else None
        ),
        "expected_hash": expected_hash,
    }

    try:
        _validate_patch_input(path, patch, expected_hash, root)
    except (FileNotFoundError, TypeError, ValueError) as exc:
        audit.record_event(
            trace_id=trace_id,
            tool="filesystem.apply_patch",
            action="failure",
            risk=RiskLevel.MEDIUM,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments=arguments,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        if isinstance(exc, MutationConflictError):
            return ApplyPatchResult(
                outcome=ContractOutcome.CONFLICT,
                trace_id=trace_id,
                error=make_contract_error("MUTATION_CONFLICT", str(exc)),
                path=path,
                executed=False,
                message=str(exc),
            )
        return ApplyPatchResult(
            outcome=ContractOutcome.REFUSED,
            trace_id=trace_id,
            error=make_contract_error(
                "MUTATION_REFUSED",
                "File patch request was refused by validation.",
            ),
            path=path,
            executed=False,
            message=str(exc),
        )

    try:
        request = approval.create_request(
            kind="file_patch",
            payload={
                "path": path,
                "patch": patch,
                "expected_hash": expected_hash,
                "workspace_root": str(root),
            },
            risk=RiskLevel.MEDIUM,
            risk_reason=PATCH_RISK_REASON,
            trace_id=trace_id,
        )
    except approval.ApprovalStoreCapacityError as exc:
        message = str(exc)
        audit.record_event(
            trace_id=trace_id,
            tool="filesystem.apply_patch",
            action="approval_request_refused",
            risk=RiskLevel.MEDIUM,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"request_kind": "file_patch"},
            error=message,
            error_type=type(exc).__name__,
        )
        return ApplyPatchResult(
            outcome=ContractOutcome.FAILED,
            trace_id=trace_id,
            error=make_contract_error("APPROVAL_STORE_CAPACITY", message),
            path=path,
            executed=False,
            message=message,
        )

    audit.record_event(
        trace_id=trace_id,
        tool="filesystem.apply_patch",
        action="approval_request",
        risk=RiskLevel.MEDIUM,
        approval_status=request.status,
        request_id=request.request_id,
        executed=False,
        success=True,
        duration_ms=_elapsed_ms(started),
        arguments=arguments,
    )

    return ApplyPatchResult(
        outcome=ContractOutcome.APPROVAL_REQUIRED,
        trace_id=trace_id,
        approval=request.public_handle(),
        path=path,
        executed=False,
        request_id=request.request_id,
        approval_status=request.status,
        message=(
            f"Approval required ({request.status.value}). "
            f"A trusted administrator must approve request "
            f"{request.request_id} before it can be applied."
        ),
    )


def apply_patch_approved(request_id: str, root: Path | None = None) -> ApplyPatchResult:
    """Execute exactly the patch stored in an APPROVED request.

    Single-use: the approval is consumed atomically. The patch is applied
    strictly (all hunks must match) and the final write is atomic — a failed
    patch leaves the file untouched.
    """
    tool = "filesystem.apply_patch_approved"
    root = _effective_root(root)
    request, status, consumed_ok = _load_and_consume(request_id)
    trace_id = _payload_trace_id(request)
    lifecycle_trace_id = trace_id or audit.new_trace_id()
    started = time.monotonic()

    if not consumed_ok:
        path = (
            str((request.payload or {}).get("path", "")) if request is not None else ""
        )
        status_value = status.value if status else "unknown"
        audit.record_event(
            trace_id=lifecycle_trace_id,
            tool=tool,
            action="approval_rejected",
            approval_status=status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"request_id": request_id, "path": path or None},
            error=f"Request is {status_value}; cannot execute.",
            error_type="KeyError" if status is None else "ApprovalStateError",
        )
        outcome, error = _approval_failure_contract(
            status, f"Request is {status_value}; cannot execute."
        )
        return ApplyPatchResult(
            outcome=outcome,
            trace_id=lifecycle_trace_id,
            approval=(request.public_handle() if request is not None else None),
            error=error,
            path=path,
            executed=False,
            request_id=request_id,
            approval_status=status,
            message=f"Request is {status_value}; cannot execute.",
        )

    snapshot_validated = False
    try:
        payload = _validate_payload(
            request, "file_patch", {"path", "patch", "expected_hash"}
        )
        validate_workspace_snapshot(payload, root)
        path = payload["path"]
        patch = payload["patch"]
        expected_hash = payload.get("expected_hash")
        if not isinstance(path, str):
            raise TypeError("Approval file patch snapshot is malformed")
        snapshot_validated = True

        target = _validate_patch_input(path, patch, expected_hash, root)

        original_text = _decode_utf8_text(
            path,
            _read_bounded_file_bytes(path, target),
        )

        new_text, additions, deletions = apply_patch_text(original_text, patch, path)

        bytes_before = len(original_text.encode("utf-8"))
        bytes_after = len(new_text.encode("utf-8"))
        maximum_write = min(MAX_WRITE_BYTES, MAX_FILE_SIZE)
        if bytes_after > maximum_write:
            raise ValueError(
                f"Patched content is too large (maximum {maximum_write} bytes)"
            )
        previous_hash = _sha256_file(target)
        changed = new_text != original_text

        if changed:
            _atomic_write_text(target, new_text)

        new_hash = _sha256_file(target)

    except (FileNotFoundError, TypeError, ValueError, OSError) as exc:
        audit.record_event(
            trace_id=lifecycle_trace_id,
            tool=tool,
            action="failure",
            risk=RiskLevel.MEDIUM,
            approval_status=request.status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={
                "path": str(request.payload.get("path", "")),
                "patch_chars": len(str(request.payload.get("patch", ""))),
                "expected_hash": request.payload.get("expected_hash"),
            },
            error=str(exc),
            error_type=type(exc).__name__,
        )
        if isinstance(exc, OSError):
            outcome = ContractOutcome.FAILED
            error = make_contract_error(
                "FILE_PATCH_FAILED",
                "Approved file patch failed.",
            )
        elif snapshot_validated:
            outcome = ContractOutcome.CONFLICT
            error = make_contract_error("MUTATION_CONFLICT", str(exc))
        else:
            outcome = ContractOutcome.REFUSED
            error = make_contract_error(
                "APPROVED_MUTATION_REFUSED",
                "Approved file patch no longer satisfies its protected snapshot.",
            )
        return ApplyPatchResult(
            outcome=outcome,
            trace_id=lifecycle_trace_id,
            approval=request.public_handle(),
            error=error,
            path=str(request.payload.get("path", "")),
            executed=False,
            request_id=request_id,
            approval_status=request.status,
            message=error.message,
        )

    audit.record_event(
        trace_id=lifecycle_trace_id,
        tool=tool,
        action="execute_approved",
        risk=RiskLevel.MEDIUM,
        approval_status=request.status,
        request_id=request_id,
        executed=True,
        success=True,
        duration_ms=_elapsed_ms(started),
        arguments={
            "path": path,
            "changed": changed,
            "additions": additions,
            "deletions": deletions,
            "bytes_before": bytes_before,
            "bytes_after": bytes_after,
            "previous_hash": previous_hash,
            "new_hash": new_hash,
        },
    )

    return ApplyPatchResult(
        outcome=ContractOutcome.SUCCEEDED,
        trace_id=lifecycle_trace_id,
        approval=request.public_handle(),
        path=path,
        executed=True,
        changed=changed,
        additions=additions,
        deletions=deletions,
        bytes_before=bytes_before,
        bytes_after=bytes_after,
        previous_hash=previous_hash,
        new_hash=new_hash,
        request_id=request_id,
        approval_status=request.status,
    )


# --------------------------------------------------------------------------
# MCP registration
# --------------------------------------------------------------------------


def register_filesystem_tools(mcp: MCPServer) -> None:
    """Register filesystem tools on the MCP server."""

    @mcp.tool(
        name="filesystem.read_file",
        title="Read workspace file",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def _read_file(path: str) -> ReadFileResult:
        """Read a UTF-8 text file inside the ToolHub workspace."""
        return read_file(path)

    @mcp.tool(
        name="filesystem.list_directory",
        title="List workspace directory",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def list_directory(path: str = ".") -> ListDirectoryResult:
        """List files and directories inside the ToolHub workspace."""
        return _list_directory(path)

    @mcp.tool(
        name="filesystem.write_file",
        title="Write workspace file (approval required)",
        annotations=MUTATION_ANNOTATIONS,
    )
    def _write_file(
        path: str,
        content: str,
        expected_hash: str | None = None,
        create_parents: bool = False,
    ) -> WriteFileResult:
        """Create a PENDING approval request for writing a UTF-8 text file.

        The write happens only after a trusted administrator approves the
        request out-of-band and filesystem.write_file_approved executes the
        stored snapshot.
        """
        return write_file(path, content, expected_hash, create_parents)

    @mcp.tool(
        name="filesystem.apply_patch",
        title="Apply workspace file patch (approval required)",
        annotations=MUTATION_ANNOTATIONS,
    )
    def _apply_patch(
        path: str,
        patch: str,
        expected_hash: str | None = None,
    ) -> ApplyPatchResult:
        """Create a PENDING approval request for a narrowly-scoped patch.

        The patch may modify only the requested file, and is applied only
        after out-of-band approval via filesystem.apply_patch_approved.
        """
        return apply_patch(path, patch, expected_hash)

    @mcp.tool(
        name="filesystem.write_file_approved",
        title="Execute an approved file write",
        annotations=MUTATION_ANNOTATIONS,
    )
    def _write_file_approved(request_id: str) -> WriteFileResult:
        """Execute exactly the file write stored in an APPROVED request.

        Takes only a request_id; the path/content/hash snapshot captured at
        request time is used. Single-use.
        """
        return write_file_approved(request_id)

    @mcp.tool(
        name="filesystem.apply_patch_approved",
        title="Execute an approved file patch",
        annotations=MUTATION_ANNOTATIONS,
    )
    def _apply_patch_approved(request_id: str) -> ApplyPatchResult:
        """Execute exactly the patch stored in an APPROVED request.

        Takes only a request_id; the stored snapshot is used. Single-use.
        """
        return apply_patch_approved(request_id)
