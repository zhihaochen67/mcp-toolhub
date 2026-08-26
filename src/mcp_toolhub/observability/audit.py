"""Audit / Trace subsystem v1.

A minimal, defensive, append-only JSON Lines audit log.

Security / privacy properties
-----------------------------
* Events live under the trusted ToolHub state root, outside the agent
  workspace.
* Trace IDs are cryptographically random (``secrets``) and therefore
  unpredictable and unguessable.
* The log stores metadata and bounded summaries only: no full file contents,
  no raw stdout/stderr (only their character counts), and argument values are
  truncated and redacted when they look like secrets.
* ``record_event`` never raises: if the log cannot be written, the failure is
  swallowed so auditing can never break the main tool path.
* This module has no MCP dependency: MCP-facing surfaces (e.g. the read-only
  ``toolhub.audit_recent`` tool) live in ``mcp_toolhub.tools.audit``.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_toolhub.security.paths import get_state_root

MAX_STRING_CHARS = 200
MAX_COLLECTION_ITEMS = 20
MAX_ERROR_CHARS = 500
MAX_READ_EVENTS = 100
MAX_READ_BYTES = 1_000_000

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


def new_trace_id() -> str:
    """Return a new unpredictable, unique trace ID."""
    return "trc_" + secrets.token_hex(16)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _default_audit_path() -> Path:
    return get_state_root() / "audit.jsonl"


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

        with _write_lock, open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()

        return True

    except Exception:  # noqa: BLE001 - audit is a non-fatal boundary
        # Defensive: audit must never break tool execution.
        return False


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
