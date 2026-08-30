"""Approval Engine v1.

A small, persistent, cross-process approval store for MEDIUM/HIGH-risk
shell commands.

Security properties
-------------------
* Approval decisions are made out-of-band by a trusted local administrator
  (``mcp-toolhub-admin``). The MCP agent has no tool that can approve,
  reject, or mutate requests: it can only create PENDING requests and run
  already-APPROVED ones.
* Request IDs are cryptographically random (``secrets``), so the agent cannot
  predict or forge a request ID for a command it invented.
* The store lives under the trusted per-user ToolHub state root and is written
  atomically (temp file + ``os.replace``) under a
  cross-process advisory lock, so the CLI and the MCP server can safely share
  it as separate processes.
* Approvals are single-use: the only path from APPROVED to execution goes
  through an atomic APPROVED -> CONSUMED transition, which prevents replay.
* Requests expire after a TTL and are never executed once EXPIRED.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcp_toolhub.contracts import (
    ApprovalHandle,
    ApprovalStatus,
    resume_tool_for_kind,
)
from mcp_toolhub.observability.audit import new_trace_id
from mcp_toolhub.security.paths import get_state_root
from mcp_toolhub.security.risk import RiskLevel

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class ApprovalStoreError(RuntimeError):
    """The trusted approval store is malformed or incompatible."""


class ApprovalStoreCapacityError(ApprovalStoreError):
    """A new request would exceed a fixed approval-store capacity limit."""

    def __init__(self, dimension: str, *, resulting: int, limit: int) -> None:
        if dimension == "records":
            detail = f"resulting record count {resulting} exceeds limit {limit}"
        elif dimension == "bytes":
            detail = (
                f"resulting serialized size {resulting} bytes exceeds limit {limit}"
            )
        else:  # pragma: no cover - internal misuse guard
            raise ValueError(f"Unsupported approval capacity dimension: {dimension}")

        self.dimension = dimension
        self.resulting = resulting
        self.limit = limit
        super().__init__(
            f"Approval store capacity reached: {detail}. A trusted administrator "
            "should prune old terminal approvals with `mcp-toolhub-admin prune "
            "approvals --older-than-days N` and repeat with `--apply`."
        )


class ApprovalRequest(BaseModel):
    """An immutable-on-approval description of an action awaiting approval.

    ``kind="shell"`` requests carry ``program``/``args``/``cwd``; mutation
    requests (``file_write`` / ``file_patch``) carry their exact snapshot in
    ``payload``. Only bounded metadata of mutations should ever be shown or
    logged outside the secure store.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str

    kind: str = "shell"
    payload: dict = Field(default_factory=dict)

    program: str = ""
    args: list[str] = Field(default_factory=list)
    cwd: str = "."
    timeout_seconds: int = 20

    risk: RiskLevel
    risk_reason: str

    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    trace_id: str
    resume_tool: str

    def public_handle(self) -> ApprovalHandle:
        """Return lifecycle metadata safe for the agent-facing contract."""
        return ApprovalHandle(
            request_id=self.request_id,
            status=self.status,
            expires_at=self.expires_at,
            resume_tool=self.resume_tool,
        )


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_TTL_SECONDS = 300  # 5 minutes
STORE_VERSION = 2
_READABLE_STORE_VERSIONS = frozenset({1, STORE_VERSION})

MAX_APPROVAL_RECORDS = 10_000
MAX_APPROVAL_STORE_BYTES = 16 * 1024 * 1024

LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_SECONDS = 0.05


@dataclass(frozen=True)
class ApprovalPruneResult:
    """Aggregate-only result for trusted approval-store maintenance."""

    apply_requested: bool
    changed: bool
    cutoff: datetime
    total: int
    eligible: int
    retained: int
    eligible_by_status: dict[ApprovalStatus, int]


def _now() -> datetime:
    return datetime.now(UTC)


def _default_store_path() -> Path:
    return get_state_root() / "approvals.json"


def _default_ttl_seconds() -> int:
    value = os.environ.get("TOOLHUB_APPROVAL_TTL_SECONDS")
    if value:
        try:
            return max(0, int(value))
        except ValueError:
            pass
    return DEFAULT_TTL_SECONDS


def _new_request_id() -> str:
    """Cryptographically random, unforgeable request ID."""
    return "req_" + secrets.token_hex(16)


# --------------------------------------------------------------------------
# Persistent JSON store (atomic, locked)
# --------------------------------------------------------------------------


def _read_store(store_path: Path) -> dict[str, ApprovalRequest]:
    """Read the store without locking. Atomic replace guarantees a reader sees
    either the old or the new file, never a torn write."""
    if not store_path.exists():
        return {}

    try:
        raw = json.loads(store_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ApprovalStoreError("Approval store is unreadable or malformed.") from exc

    if not isinstance(raw, dict):
        raise ApprovalStoreError("Approval store must contain a JSON object.")

    version = raw.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ApprovalStoreError("Approval store version is missing or malformed.")
    if version not in _READABLE_STORE_VERSIONS:
        raise ApprovalStoreError(f"Unsupported approval store version: {version}")

    payload = raw.get("requests")
    if not isinstance(payload, dict):
        raise ApprovalStoreError("Approval store requests are missing or malformed.")

    requests: dict[str, ApprovalRequest] = {}

    for request_id, data in payload.items():
        if not isinstance(request_id, str) or not isinstance(data, dict):
            raise ApprovalStoreError("Approval store contains a malformed request.")

        normalized = dict(data)
        if version == 1:
            request_payload = normalized.get("payload")
            payload_trace = (
                request_payload.get("trace_id")
                if isinstance(request_payload, dict)
                else None
            )
            if not isinstance(payload_trace, str) or not payload_trace:
                legacy_material = {
                    "store_request_id": request_id,
                    "record": normalized,
                }
                encoded = json.dumps(
                    legacy_material,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                payload_trace = "trc_legacy_" + hashlib.sha256(encoded).hexdigest()[:32]
            normalized.setdefault("trace_id", payload_trace)
            try:
                normalized.setdefault(
                    "resume_tool",
                    resume_tool_for_kind(str(normalized.get("kind", "shell"))),
                )
            except ValueError as exc:
                raise ApprovalStoreError(
                    "Approval store contains an unsupported request kind."
                ) from exc

        try:
            request = ApprovalRequest.model_validate(normalized)
        except ValidationError as exc:
            raise ApprovalStoreError(
                f"Approval store request is malformed: {request_id}"
            ) from exc

        if request.request_id != request_id:
            raise ApprovalStoreError(
                "Approval request ID does not match its store key."
            )
        try:
            expected_resume = resume_tool_for_kind(request.kind)
        except ValueError as exc:
            raise ApprovalStoreError(
                "Approval store contains an unsupported request kind."
            ) from exc
        if request.resume_tool != expected_resume:
            raise ApprovalStoreError("Approval request resume tool is invalid.")
        requests[request_id] = request

    return requests


def _serialize_store(requests: dict[str, ApprovalRequest]) -> bytes:
    """Return the complete deterministic UTF-8 representation persisted to disk."""
    payload = {
        "version": STORE_VERSION,
        "requests": {
            request_id: request.model_dump(mode="json")
            for request_id, request in sorted(requests.items())
        },
    }

    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def _write_serialized_store(store_path: Path, serialized: bytes) -> None:
    """Atomically persist one already-serialized store representation."""
    store_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = store_path.parent / f".approvals-{secrets.token_hex(8)}.tmp"

    try:
        with open(tmp_path, "xb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, store_path)

    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _write_store(
    store_path: Path,
    requests: dict[str, ApprovalRequest],
) -> None:
    """Serialize and atomically write the store."""
    _write_serialized_store(store_path, _serialize_store(requests))


def _acquire_os_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_os_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _is_lock_contention(exc: OSError) -> bool:
    if os.name == "nt":
        winerror = getattr(exc, "winerror", None)
        if winerror is not None:
            return winerror in {33, 36}
    return exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


@contextmanager
def _store_lock(store_path: Path) -> Iterator[None]:
    """Hold an OS-backed cross-process lock for one store critical section."""
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store_path.with_name(store_path.name + ".lock")
    # Keep this sidecar stable: unlinking or replacing it could let contenders
    # lock different underlying files and both enter the critical section.
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = os.open(lock_path, open_flags, 0o600)
    locked = False

    try:
        while True:
            try:
                _acquire_os_lock(descriptor)
                locked = True
                break
            except OSError as exc:
                if not _is_lock_contention(exc):
                    raise

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Approval store lock acquisition timed out."
                    ) from exc
                time.sleep(min(_LOCK_RETRY_SECONDS, remaining))

        yield
    finally:
        if locked:
            try:
                _release_os_lock(descriptor)
            except OSError:
                pass
        try:
            os.close(descriptor)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Expiration helpers
# --------------------------------------------------------------------------


def _expired(request: ApprovalRequest, now: datetime | None = None) -> bool:
    if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
        return (now or _now()) >= request.expires_at
    return False


def _prune_timestamp(
    request: ApprovalRequest,
    *,
    now: datetime,
) -> tuple[ApprovalStatus, datetime] | None:
    """Return the effective terminal status and its deterministic age basis."""
    if request.status in {ApprovalStatus.REJECTED, ApprovalStatus.CONSUMED}:
        if request.decided_at is None:
            return None
        return request.status, request.decided_at

    if request.status == ApprovalStatus.EXPIRED:
        return request.status, request.decided_at or request.expires_at

    if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and _expired(
        request, now
    ):
        return ApprovalStatus.EXPIRED, request.expires_at

    return None


def _approval_prune_plan(
    requests: dict[str, ApprovalRequest],
    *,
    cutoff: datetime,
    now: datetime,
) -> tuple[set[str], dict[ApprovalStatus, int]]:
    eligible_ids: set[str] = set()
    by_status = {
        ApprovalStatus.REJECTED: 0,
        ApprovalStatus.EXPIRED: 0,
        ApprovalStatus.CONSUMED: 0,
    }

    try:
        for request_id, request in requests.items():
            terminal = _prune_timestamp(request, now=now)
            if terminal is None:
                continue
            status, timestamp = terminal
            if timestamp <= cutoff:
                eligible_ids.add(request_id)
                by_status[status] += 1
    except TypeError as exc:
        raise ApprovalStoreError(
            "Approval store contains an invalid timestamp."
        ) from exc

    return eligible_ids, by_status


def _apply_decision(
    request_id: str,
    *,
    allowed: set[ApprovalStatus],
    new_status: ApprovalStatus,
    store_path: Path,
    now: datetime | None = None,
) -> tuple[ApprovalRequest | None, bool]:
    """Atomically transition a request to ``new_status``.

    Returns ``(request, changed)``:

    * ``(None, False)`` when the request does not exist.
    * ``(request, True)`` when a transition (or expiry marking) was persisted.
    * ``(request, False)`` when the request exists but was not in ``allowed``
      and was therefore left unchanged.
    """
    current = now or _now()

    with _store_lock(store_path):
        store = _read_store(store_path)
        request = store.get(request_id)

        if request is None:
            return None, False

        if _expired(request, current):
            request.status = ApprovalStatus.EXPIRED
            request.decided_at = current
            store[request_id] = request
            _write_store(store_path, store)
            return request, True

        if request.status not in allowed:
            return request, False

        request.status = new_status
        request.decided_at = current
        store[request_id] = request
        _write_store(store_path, store)

        return request, True


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def create_request(
    *,
    program: str = "",
    args: list[str] | None = None,
    cwd: str = ".",
    timeout_seconds: int = 20,
    risk: RiskLevel,
    risk_reason: str,
    kind: str = "shell",
    payload: dict | None = None,
    trace_id: str | None = None,
    ttl_seconds: int | None = None,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Create and persist a PENDING approval request.

    ``kind``/``payload`` carry non-shell mutations (file writes, patches);
    the payload is the exact snapshot that approved execution will replay.
    """
    path = store_path or _default_store_path()
    ttl = _default_ttl_seconds() if ttl_seconds is None else ttl_seconds
    current = now or _now()

    request = ApprovalRequest(
        request_id=_new_request_id(),
        kind=kind,
        payload=dict(payload or {}),
        program=program,
        args=list(args or []),
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        risk=risk,
        risk_reason=risk_reason,
        status=ApprovalStatus.PENDING,
        created_at=current,
        expires_at=current + timedelta(seconds=ttl),
        decided_at=None,
        trace_id=trace_id or new_trace_id(),
        resume_tool=resume_tool_for_kind(kind),
    )

    with _store_lock(path):
        store = _read_store(path)
        if request.request_id in store:
            raise ApprovalStoreError("Generated duplicate approval request ID.")

        resulting_count = len(store) + 1
        if resulting_count > MAX_APPROVAL_RECORDS:
            raise ApprovalStoreCapacityError(
                "records",
                resulting=resulting_count,
                limit=MAX_APPROVAL_RECORDS,
            )

        store[request.request_id] = request
        serialized = _serialize_store(store)
        serialized_size = len(serialized)
        if serialized_size > MAX_APPROVAL_STORE_BYTES:
            raise ApprovalStoreCapacityError(
                "bytes",
                resulting=serialized_size,
                limit=MAX_APPROVAL_STORE_BYTES,
            )

        _write_serialized_store(path, serialized)

    return request


def get_request(
    request_id: str,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest | None:
    """Return a request, or ``None`` when unknown. Lazily reflects EXPIRED."""
    path = store_path or _default_store_path()
    current = now or _now()

    request = _read_store(path).get(request_id)

    if request is None:
        return None

    if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and _expired(
        request, current
    ):
        _apply_decision(
            request_id,
            allowed={ApprovalStatus.PENDING, ApprovalStatus.APPROVED},
            new_status=ApprovalStatus.EXPIRED,
            store_path=path,
            now=current,
        )
        return request.model_copy(update={"status": ApprovalStatus.EXPIRED})

    return request


def observe_request(
    request_id: str,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest | None:
    """Observe effective request state without writing or consuming anything."""
    path = store_path or _default_store_path()
    current = now or _now()
    request = _read_store(path).get(request_id)
    if request is None:
        return None
    if _expired(request, current):
        return request.model_copy(update={"status": ApprovalStatus.EXPIRED})
    return request


def approve_request(
    request_id: str,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Approve a PENDING request. Raises on unknown/invalid/expired requests."""
    path = store_path or _default_store_path()
    result, changed = _apply_decision(
        request_id,
        allowed={ApprovalStatus.PENDING},
        new_status=ApprovalStatus.APPROVED,
        store_path=path,
        now=now,
    )

    if result is None:
        raise KeyError(f"Unknown approval request: {request_id}")

    if result.status == ApprovalStatus.EXPIRED:
        raise ValueError(f"Approval request expired: {request_id}")

    if not changed or result.status != ApprovalStatus.APPROVED:
        raise ValueError(f"Approval request is {result.status.value}: {request_id}")

    return result


def reject_request(
    request_id: str,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Reject a PENDING request. Raises on unknown/invalid/expired requests."""
    path = store_path or _default_store_path()
    result, changed = _apply_decision(
        request_id,
        allowed={ApprovalStatus.PENDING},
        new_status=ApprovalStatus.REJECTED,
        store_path=path,
        now=now,
    )

    if result is None:
        raise KeyError(f"Unknown approval request: {request_id}")

    if result.status == ApprovalStatus.EXPIRED:
        raise ValueError(f"Approval request expired: {request_id}")

    if not changed or result.status != ApprovalStatus.REJECTED:
        raise ValueError(f"Approval request is {result.status.value}: {request_id}")

    return result


def consume_request(
    request_id: str,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest | None:
    """Atomically consume an APPROVED request (single-use).

    Returns the CONSUMED request on success, or ``None`` when the request is
    unknown, not APPROVED, or EXPIRED.
    """
    path = store_path or _default_store_path()
    result, changed = _apply_decision(
        request_id,
        allowed={ApprovalStatus.APPROVED},
        new_status=ApprovalStatus.CONSUMED,
        store_path=path,
        now=now,
    )

    if result is None:
        return None

    if changed and result.status == ApprovalStatus.CONSUMED:
        return result

    return None


def list_requests(
    store_path: Path | None = None,
    now: datetime | None = None,
) -> list[ApprovalRequest]:
    """Return all requests, oldest first, reflecting lazy expiration."""
    path = store_path or _default_store_path()
    current = now or _now()

    results: list[ApprovalRequest] = []

    for request in _read_store(path).values():
        if request.status in {
            ApprovalStatus.PENDING,
            ApprovalStatus.APPROVED,
        } and _expired(request, current):
            request = request.model_copy(update={"status": ApprovalStatus.EXPIRED})
        results.append(request)

    results.sort(key=lambda r: r.created_at)
    return results


def prune_requests(
    older_than_days: int,
    *,
    apply: bool = False,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalPruneResult:
    """Plan or apply pruning of sufficiently old, effectively terminal requests.

    Dry runs read without writing. Apply mode acquires the approval-store lock,
    re-reads the store, and recomputes eligibility before an atomic rewrite so a
    previously observed plan is never used as deletion authority.
    """
    if isinstance(older_than_days, bool) or not isinstance(older_than_days, int):
        raise TypeError("older_than_days must be an integer")
    if older_than_days < 0:
        raise ValueError("older_than_days must be at least 0")

    path = store_path or _default_store_path()
    current = now or _now()
    try:
        cutoff = current - timedelta(days=older_than_days)
    except OverflowError as exc:
        raise ValueError("older_than_days is too large") from exc

    def evaluate(requests: dict[str, ApprovalRequest]) -> ApprovalPruneResult:
        eligible_ids, by_status = _approval_prune_plan(
            requests,
            cutoff=cutoff,
            now=current,
        )
        changed = apply and bool(eligible_ids)
        if changed:
            retained = {
                request_id: request
                for request_id, request in requests.items()
                if request_id not in eligible_ids
            }
            _write_store(path, retained)

        return ApprovalPruneResult(
            apply_requested=apply,
            changed=changed,
            cutoff=cutoff,
            total=len(requests),
            eligible=len(eligible_ids),
            retained=len(requests) - len(eligible_ids),
            eligible_by_status=by_status,
        )

    if not apply:
        return evaluate(_read_store(path))

    with _store_lock(path):
        return evaluate(_read_store(path))
