"""Audit / Trace subsystem v1.

A minimal, defensive, append-only JSON Lines audit log.

Security / privacy properties
-----------------------------
* Events live under the trusted ToolHub state root, outside the agent
  workspace.
* Trace IDs are cryptographically random (``secrets``) and therefore
  unpredictable and unguessable.
* The log stores metadata and bounded summaries only: no full file contents,
  no raw stdout/stderr (only their character counts and bounded capture byte
  counters), and argument values are truncated and redacted when they look
  like secrets.
* ``record_event`` never raises: if the log cannot be written, the failure is
  swallowed so auditing can never break the main tool path.
* This module has no MCP dependency: MCP-facing surfaces (e.g. the read-only
  ``toolhub.audit_recent`` tool) live in ``mcp_toolhub.tools.audit``.
"""

from __future__ import annotations

import errno
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_toolhub.security.paths import get_state_root
from mcp_toolhub.security.state_permissions import open_trusted_file

if os.name == "nt":
    import msvcrt
else:
    import fcntl

MAX_STRING_CHARS = 200
MAX_COLLECTION_ITEMS = 20
MAX_ERROR_CHARS = 500
MAX_READ_EVENTS = 100
MAX_READ_BYTES = 1_000_000
MAX_COMPACTION_EVENTS = 100_000
MAX_COMPACTION_LINE_BYTES = 1_000_000

AUDIT_LOCK_TIMEOUT_SECONDS = 5.0
_AUDIT_LOCK_RETRY_SECONDS = 0.05

_SENSITIVE_NAME = re.compile(
    r"(password|passwd|pwd|token|secret|api[-_.]?key|credential"
    r"|authorization|auth|cookie|private[-_.]?key)",
    re.IGNORECASE,
)

_SENSITIVE_ASSIGNMENT = re.compile(
    r"([A-Za-z0-9_.-]*(?:password|passwd|token|secret|api[-_.]?key"
    r"|credential|authorization|cookie|private[-_.]?key)[A-Za-z0-9_.-]*)"
    r"\s*=\s*([^\s\"',;]+)",
    re.IGNORECASE,
)

_write_lock = threading.Lock()


class AuditMaintenanceError(RuntimeError):
    """The audit log cannot be compacted without risking data loss."""


@dataclass(frozen=True)
class AuditCompactionResult:
    """Aggregate-only result for trusted audit maintenance."""

    apply_requested: bool
    changed: bool
    total: int
    retained: int
    removed: int


@dataclass(frozen=True)
class _AuditScan:
    total: int
    retained: int
    retained_offset: int


def new_trace_id() -> str:
    """Return a new unpredictable, unique trace ID."""
    return "trc_" + secrets.token_hex(16)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _default_audit_path() -> Path:
    return get_state_root() / "audit.jsonl"


@contextmanager
def _audit_file_lock(audit_path: Path) -> Iterator[None]:
    """Hold an OS-backed cross-process lock for one audit critical section."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = audit_path.with_name(audit_path.name + ".lock")
    # Keep this sidecar stable: unlinking or replacing it could let contenders
    # lock different underlying files and both enter the critical section.
    deadline = time.monotonic() + AUDIT_LOCK_TIMEOUT_SECONDS
    open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = open_trusted_file(lock_path, open_flags)
    locked = False

    try:
        while True:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError as exc:
                contention = exc.errno in {
                    errno.EACCES,
                    errno.EAGAIN,
                    errno.EDEADLK,
                } or getattr(exc, "winerror", None) in {33, 36}
                if not contention:
                    raise

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Audit log lock acquisition timed out.") from exc
                time.sleep(min(_AUDIT_LOCK_RETRY_SECONDS, remaining))

        yield
    finally:
        if locked:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(descriptor)
        except OSError:
            pass


@contextmanager
def _audit_write_lock(audit_path: Path) -> Iterator[None]:
    """Serialize audit append/rewrite operations within and across processes."""
    with _write_lock, _audit_file_lock(audit_path):
        yield


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"...[+{len(value) - limit} chars]"


def redact_text(value: str) -> str:
    """Mask obvious secret assignments such as ``TOKEN=abc`` in free text."""
    return _SENSITIVE_ASSIGNMENT.sub(r"\1=***", value)


def sanitize_text(value: str, *, limit: int = MAX_STRING_CHARS) -> str:
    """Redact obvious secrets and bound the length of a text value."""
    return _truncate(redact_text(value), limit)


def sanitize_argument(argument: str, *, limit: int = MAX_STRING_CHARS) -> str:
    """Sanitize a single command-line argument.

    ``--token=abc`` and ``TOKEN=abc`` become ``--token=***`` / ``TOKEN=***``.
    """
    match = re.match(r"^(--?[A-Za-z0-9_.-]+)=(.*)$", argument, re.DOTALL)
    if match and _SENSITIVE_NAME.search(match.group(1)):
        return f"{match.group(1)}=***"

    match = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$", argument, re.DOTALL)
    if match and _SENSITIVE_NAME.search(match.group(1)):
        return f"{match.group(1)}=***"

    return sanitize_text(argument, limit=limit)


def sanitize_args(
    args: list[str],
    *,
    max_args: int = MAX_COLLECTION_ITEMS,
    max_len: int = MAX_STRING_CHARS,
) -> list[str]:
    """Sanitize a command-line argument list.

    Sensitive flags (``--password``, ``--token``, ...) keep their name but
    have their following value replaced with ``***``.
    """
    result: list[str] = []
    index = 0
    total = len(args)

    while index < total and len(result) < max_args:
        argument = args[index]

        is_sensitive_flag = bool(
            re.fullmatch(r"--?[A-Za-z0-9_.-]+", argument)
        ) and bool(_SENSITIVE_NAME.search(argument))

        if (
            is_sensitive_flag
            and index + 1 < total
            and not args[index + 1].startswith("-")
        ):
            result.append(argument)
            if len(result) < max_args:
                result.append("***")
            index += 2
            continue

        result.append(sanitize_argument(argument, limit=max_len))
        index += 1

    if index < total:
        result.append(f"...[{total - index} more args]")

    return result


def _sanitize_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively bound and redact an arbitrary JSON-able value."""
    if depth > 4:
        return "..."

    if isinstance(value, str):
        return sanitize_text(value)

    if isinstance(value, (int, float, bool)) or value is None:
        return value

    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return sanitize_args(value)

        items = [
            _sanitize_value(item, depth=depth + 1)
            for item in value[:MAX_COLLECTION_ITEMS]
        ]
        if len(value) > MAX_COLLECTION_ITEMS:
            items.append(f"...[{len(value) - MAX_COLLECTION_ITEMS} more items]")
        return items

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_COLLECTION_ITEMS]:
            result[str(key)[:100]] = _sanitize_value(item, depth=depth + 1)
        if len(value) > MAX_COLLECTION_ITEMS:
            result["..."] = f"[{len(value) - MAX_COLLECTION_ITEMS} more keys]"
        return result

    return sanitize_text(str(value))


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def record_event(
    *,
    tool: str,
    action: str,
    trace_id: str | None = None,
    timestamp: str | None = None,
    risk: Any = None,
    approval_status: Any = None,
    request_id: str | None = None,
    executed: bool | None = None,
    success: bool | None = None,
    duration_ms: int | None = None,
    returncode: int | None = None,
    arguments: Any = None,
    cwd: str | None = None,
    error: str | None = None,
    error_type: str | None = None,
    stdout_chars: int | None = None,
    stderr_chars: int | None = None,
    extra: Any = None,
    audit_path: Path | None = None,
) -> bool:
    """Append one audit event to the JSONL log.

    Never raises: any logging failure returns ``False`` and is otherwise
    ignored, so tool execution can never be broken by the audit subsystem.
    Returns ``True`` when the event was appended successfully.
    """
    try:
        event: dict[str, Any] = {
            "trace_id": trace_id or new_trace_id(),
            "timestamp": timestamp or _now_iso(),
            "tool": sanitize_text(str(tool)),
            "action": sanitize_text(str(action)),
        }

        if risk is not None:
            event["risk"] = _enum_value(risk)
        if approval_status is not None:
            event["approval_status"] = _enum_value(approval_status)
        if request_id is not None:
            event["request_id"] = sanitize_text(str(request_id))
        if executed is not None:
            event["executed"] = bool(executed)
        if success is not None:
            event["success"] = bool(success)
        if duration_ms is not None:
            event["duration_ms"] = int(duration_ms)
        if returncode is not None:
            event["returncode"] = int(returncode)
        if arguments is not None:
            event["arguments"] = _sanitize_value(arguments)
        if cwd is not None:
            event["cwd"] = sanitize_text(str(cwd))
        if error is not None:
            event["error"] = sanitize_text(str(error), limit=MAX_ERROR_CHARS)
        if error_type is not None:
            event["error_type"] = sanitize_text(str(error_type))
        if stdout_chars is not None:
            event["stdout_chars"] = int(stdout_chars)
        if stderr_chars is not None:
            event["stderr_chars"] = int(stderr_chars)
        if extra is not None:
            event["extra"] = _sanitize_value(extra)

        path = audit_path or _default_audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"

        with _audit_write_lock(path):
            open_flags = (
                os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_BINARY", 0)
            )
            descriptor = open_trusted_file(path, open_flags)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()

        return True

    except Exception:  # noqa: BLE001 - audit is a non-fatal boundary
        # Defensive: audit must never break tool execution.
        return False


def _scan_for_compaction(
    path: Path,
    keep_last: int,
) -> _AuditScan:
    """Validate the complete JSONL file and locate the retained byte suffix."""
    if not path.exists():
        return _AuditScan(total=0, retained=0, retained_offset=0)

    offsets: deque[int] = deque(maxlen=max(1, keep_last))
    total = 0
    position = 0

    try:
        descriptor = open_trusted_file(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        with os.fdopen(descriptor, "rb") as handle:
            while True:
                line = handle.readline(MAX_COMPACTION_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_COMPACTION_LINE_BYTES:
                    raise AuditMaintenanceError(
                        "Audit log contains an oversized or incomplete event."
                    )
                if not line.endswith(b"\n") or not line.strip():
                    raise AuditMaintenanceError(
                        "Audit log contains an incomplete or empty event."
                    )
                try:
                    event = json.loads(line)
                except (
                    json.JSONDecodeError,
                    RecursionError,
                    UnicodeDecodeError,
                ) as exc:
                    raise AuditMaintenanceError(
                        "Audit log contains malformed JSON."
                    ) from exc
                if not isinstance(event, dict):
                    raise AuditMaintenanceError(
                        "Audit log contains a non-object event."
                    )

                if keep_last:
                    offsets.append(position)
                position += len(line)
                total += 1
    except AuditMaintenanceError:
        raise
    except OSError as exc:
        raise AuditMaintenanceError("Audit log could not be read safely.") from exc

    retained = min(total, keep_last)
    retained_offset = offsets[0] if offsets else position
    return _AuditScan(
        total=total,
        retained=retained,
        retained_offset=retained_offset,
    )


def _write_compacted_audit(
    path: Path,
    retained_offset: int,
) -> None:
    """Atomically replace the log with its exact retained byte suffix."""
    temporary = path.parent / f".audit-{secrets.token_hex(8)}.tmp"

    try:
        source_descriptor = open_trusted_file(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        with os.fdopen(source_descriptor, "rb") as source:
            destination_descriptor = open_trusted_file(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            )
            with os.fdopen(destination_descriptor, "wb") as destination:
                source.seek(retained_offset)
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def compact_audit(
    keep_last: int,
    *,
    apply: bool = False,
    audit_path: Path | None = None,
) -> AuditCompactionResult:
    """Plan or atomically retain only the newest complete audit events.

    Apply mode scans and rewrites while holding the same cross-process lock as
    normal appends. A malformed or incomplete line aborts before replacement.
    """
    if isinstance(keep_last, bool) or not isinstance(keep_last, int):
        raise TypeError("keep_last must be an integer")
    if not 0 <= keep_last <= MAX_COMPACTION_EVENTS:
        raise ValueError(f"keep_last must be between 0 and {MAX_COMPACTION_EVENTS}")

    path = audit_path or _default_audit_path()

    def evaluate() -> AuditCompactionResult:
        scan = _scan_for_compaction(path, keep_last)
        removed = scan.total - scan.retained
        changed = apply and removed > 0
        if changed:
            try:
                _write_compacted_audit(path, scan.retained_offset)
            except OSError as exc:
                raise AuditMaintenanceError(
                    "Audit log could not be replaced safely."
                ) from exc
        return AuditCompactionResult(
            apply_requested=apply,
            changed=changed,
            total=scan.total,
            retained=scan.retained,
            removed=removed,
        )

    if not apply:
        return evaluate()

    try:
        with _audit_write_lock(path):
            return evaluate()
    except AuditMaintenanceError:
        raise
    except OSError as exc:
        raise AuditMaintenanceError(
            "Audit compaction could not acquire the audit lock."
        ) from exc


def _read_last_lines(path: Path, limit: int) -> list[str]:
    """Read up to ``limit`` trailing non-empty lines without loading the
    whole file, bounded by ``MAX_READ_BYTES``."""
    lines: list[str] = []

    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()

            chunk_size = 8192
            buffer = b""
            read_total = 0
            position = size

            while position > 0 and len(lines) < limit and read_total < MAX_READ_BYTES:
                step = min(chunk_size, position)
                position -= step
                handle.seek(position)
                buffer = handle.read(step) + buffer
                read_total += step

                parts = buffer.split(b"\n")
                buffer = parts[0]

                for part in reversed(parts[1:]):
                    if part.strip():
                        lines.append(part.decode("utf-8", errors="replace"))
                        if len(lines) >= limit:
                            break

            if buffer.strip() and len(lines) < limit:
                lines.append(buffer.decode("utf-8", errors="replace"))

    except OSError:
        return []

    lines.reverse()
    return lines[-limit:]


def read_recent(
    limit: int = MAX_READ_EVENTS,
    audit_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return the most recent audit events (oldest to newest).

    Read-only, bounded to ``MAX_READ_EVENTS``, and resilient to corrupt
    lines (they are skipped).
    """
    limit = max(1, min(int(limit), MAX_READ_EVENTS))
    path = audit_path or _default_audit_path()

    if not path.exists():
        return []

    events: list[dict[str, Any]] = []

    for line in _read_last_lines(path, limit):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict):
            events.append(data)

    return events
