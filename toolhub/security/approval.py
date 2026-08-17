"""Approval Engine v1.

A small, persistent, cross-process approval store for MEDIUM/HIGH-risk
shell commands.

Security properties
-------------------
* Approval decisions are made out-of-band by a trusted local administrator
  (``python -m toolhub.admin``). The MCP agent has no tool that can approve,
  reject, or mutate requests: it can only create PENDING requests and run
  already-APPROVED ones.
* Request IDs are cryptographically random (``secrets``), so the agent cannot
  predict or forge a request ID for a command it invented.
* The store lives outside the agent workspace (``.toolhub/approvals.json`` by
  default) and is written atomically (temp file + ``os.replace``) under a
  cross-process advisory lock, so the CLI and the MCP server can safely share
  it as separate processes.
* Approvals are single-use: the only path from APPROVED to execution goes
  through an atomic APPROVED -> CONSUMED transition, which prevents replay.
* Requests expire after a TTL and are never executed once EXPIRED.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator

from pydantic import BaseModel

from toolhub.security.paths import PROJECT_ROOT
from toolhub.security.risk import RiskLevel


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ApprovalRequest(BaseModel):
    """An immutable-on-approval description of a command awaiting approval."""

    request_id: str
    program: str
    args: list[str]
    cwd: str
    timeout_seconds: int

    risk: RiskLevel
    risk_reason: str

    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_TTL_SECONDS = 300  # 5 minutes
DEFAULT_STORE_PATH = PROJECT_ROOT / ".toolhub" / "approvals.json"
STORE_VERSION = 1

LOCK_TIMEOUT_SECONDS = 5.0
LOCK_STALE_SECONDS = 15.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _default_store_path() -> Path:
    value = os.environ.get("TOOLHUB_APPROVAL_STORE")
    if value:
        return Path(value).expanduser().resolve()
    return DEFAULT_STORE_PATH


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
    except (json.JSONDecodeError, OSError):
        # A corrupt/unreadable store contains no approvals -> fail closed.
        return {}

    if not isinstance(raw, dict):
        return {}

    payload = raw.get("requests")
    if not isinstance(payload, dict):
        return {}

    requests: dict[str, ApprovalRequest] = {}

    for request_id, data in payload.items():
        try:
            requests[request_id] = ApprovalRequest.model_validate(data)
        except Exception:
            # Skip malformed entries rather than failing the whole store.
            continue

    return requests


def _write_store(
    store_path: Path,
    requests: dict[str, ApprovalRequest],
) -> None:
    """Write the store atomically: temp file + fsync + os.replace."""
    store_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "version": STORE_VERSION,
        "requests": {
            request_id: request.model_dump(mode="json")
            for request_id, request in sorted(requests.items())
        },
    }

    tmp_path = store_path.parent / f".approvals-{secrets.token_hex(8)}.tmp"

    try:
        with open(tmp_path, "x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, store_path)

    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


@contextmanager
def _store_lock(store_path: Path) -> Iterator[None]:
    """Advisory cross-process lock via an O_EXCL lock file, with stale-lock
    recovery so a crashed writer cannot wedge the store forever."""
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store_path.with_name(store_path.name + ".lock")

    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    fd: int | None = None

    while True:
        try:
            fd = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
            break
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > LOCK_STALE_SECONDS:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Approval store is locked: {lock_path}"
                )
            time.sleep(0.05)

    try:
        if fd is not None:
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.close(fd)
            fd = None

        yield

    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Expiration helpers
# --------------------------------------------------------------------------


def _expired(request: ApprovalRequest, now: datetime | None = None) -> bool:
    if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
        return (now or _now()) > request.expires_at
    return False


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
    program: str,
    args: list[str] | None = None,
    cwd: str = ".",
    timeout_seconds: int = 20,
    risk: RiskLevel,
    risk_reason: str,
    ttl_seconds: int | None = None,
    store_path: Path | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Create and persist a PENDING approval request."""
    path = store_path or _default_store_path()
    ttl = _default_ttl_seconds() if ttl_seconds is None else ttl_seconds
    current = now or _now()

    request = ApprovalRequest(
        request_id=_new_request_id(),
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
    )

    with _store_lock(path):
        store = _read_store(path)
        store[request.request_id] = request
        _write_store(path, store)

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
        raise ValueError(
            f"Approval request is {result.status.value}: {request_id}"
        )

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
        raise ValueError(
            f"Approval request is {result.status.value}: {request_id}"
        )

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
        if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and _expired(
            request, current
        ):
            request = request.model_copy(update={"status": ApprovalStatus.EXPIRED})
        results.append(request)

    results.sort(key=lambda r: r.created_at)
    return results
