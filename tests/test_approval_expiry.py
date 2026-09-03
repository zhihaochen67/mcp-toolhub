"""Deterministic expiry checks at the locked approval transition boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.risk import RiskLevel

CREATED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.fixture(params=["approve", "reject", "consume"])
def transition(request):
    return getattr(approval, f"{request.param}_request")


def _create_request(transition):
    request = approval.create_request(
        program="python",
        args=["--version"],
        risk=RiskLevel.MEDIUM,
        risk_reason="expiry test",
        ttl_seconds=60,
        now=CREATED_AT,
    )
    if transition is approval.consume_request:
        return approval.approve_request(request.request_id, now=CREATED_AT)
    return request


def _assert_expired(transition, request_id, **kwargs):
    if transition is approval.consume_request:
        assert transition(request_id, **kwargs) is None
    else:
        with pytest.raises(ValueError, match="Approval request expired:"):
            transition(request_id, **kwargs)


def _unexpected_clock():
    raise AssertionError("explicit now must not consult the production clock")


@pytest.mark.parametrize("explicit_now", [False, True], ids=["normal", "explicit"])
@pytest.mark.parametrize("offset_us", [-1, 0, 1], ids=["before", "at", "after"])
def test_expiry_boundary_and_persisted_timestamp(
    isolated_approval_store, monkeypatch, transition, explicit_now, offset_us
):
    request = _create_request(transition)
    effective = request.expires_at + timedelta(microseconds=offset_us)
    monkeypatch.setattr(
        approval, "_now", _unexpected_clock if explicit_now else lambda: effective
    )
    kwargs = {"now": effective} if explicit_now else {}

    if offset_us >= 0:
        _assert_expired(transition, request.request_id, **kwargs)
        expected_status = ApprovalStatus.EXPIRED
    else:
        result = transition(request.request_id, **kwargs)
        expected_status = {
            approval.approve_request: ApprovalStatus.APPROVED,
            approval.reject_request: ApprovalStatus.REJECTED,
            approval.consume_request: ApprovalStatus.CONSUMED,
        }[transition]
        assert result.status == expected_status
        assert result.decided_at == effective

    persisted = approval._read_store(isolated_approval_store)[request.request_id]
    assert persisted == request.model_copy(
        update={"status": expected_status, "decided_at": effective}
    )


@pytest.mark.parametrize("explicit_now", [False, True], ids=["normal", "explicit"])
def test_request_expires_while_waiting_for_store_lock(
    isolated_approval_store, monkeypatch, transition, explicit_now
):
    request = _create_request(transition)
    before_expiry = request.expires_at - timedelta(microseconds=1)
    after_expiry = request.expires_at + timedelta(microseconds=1)
    current = before_expiry
    waiting = Event()
    released = Event()
    acquire = approval._acquire_os_lock

    def acquire_after_holder_releases(descriptor):
        try:
            acquire(descriptor)
        except OSError as exc:
            if not approval._is_lock_contention(exc):
                raise
            # Observe real OS-lock contention, then synchronize without sleeps.
            waiting.set()
            assert released.wait(timeout=10), "store lock holder did not release"
            acquire(descriptor)

    monkeypatch.setattr(
        approval, "_now", _unexpected_clock if explicit_now else lambda: current
    )
    kwargs = {"now": before_expiry} if explicit_now else {}

    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            with approval._store_lock(isolated_approval_store):
                monkeypatch.setattr(
                    approval, "_acquire_os_lock", acquire_after_holder_releases
                )
                future = executor.submit(transition, request.request_id, **kwargs)
                assert waiting.wait(timeout=10), "transition did not contend for lock"
                assert not future.done()
                current = after_expiry
        finally:
            released.set()

        if explicit_now:
            result = future.result(timeout=10)
            assert result is not None
            assert result.decided_at == before_expiry
        elif transition is approval.consume_request:
            assert future.result(timeout=10) is None
        else:
            with pytest.raises(ValueError, match="Approval request expired:"):
                future.result(timeout=10)

    persisted = approval._read_store(isolated_approval_store)[request.request_id]
    if explicit_now:
        assert persisted == result
        assert (
            persisted.status
            == {
                approval.approve_request: ApprovalStatus.APPROVED,
                approval.reject_request: ApprovalStatus.REJECTED,
                approval.consume_request: ApprovalStatus.CONSUMED,
            }[transition]
        )
    else:
        assert persisted == request.model_copy(
            update={"status": ApprovalStatus.EXPIRED, "decided_at": after_expiry}
        )


def test_normal_transition_samples_clock_once_after_locked_store_read(
    isolated_approval_store, monkeypatch, transition
):
    request = _create_request(transition)
    effective = request.expires_at - timedelta(microseconds=1)
    lock = approval._store_lock
    read = approval._read_store
    write = approval._write_store
    locked = False
    read_finished = False
    clock_calls = 0
    writes = 0

    @contextmanager
    def tracked_lock(path):
        nonlocal locked
        with lock(path):
            locked = True
            try:
                yield
            finally:
                locked = False

    def tracked_read(path):
        nonlocal read_finished
        assert locked
        store = read(path)
        read_finished = True
        return store

    def clock():
        nonlocal clock_calls
        assert locked and read_finished
        clock_calls += 1
        assert clock_calls == 1, "expiry and decided_at must share one timestamp"
        return effective

    def tracked_write(path, store):
        nonlocal writes
        assert locked
        writes += 1
        write(path, store)

    monkeypatch.setattr(approval, "_store_lock", tracked_lock)
    monkeypatch.setattr(approval, "_read_store", tracked_read)
    monkeypatch.setattr(approval, "_write_store", tracked_write)
    monkeypatch.setattr(approval, "_now", clock)

    result = transition(request.request_id)

    assert result.decided_at == effective
    assert read(isolated_approval_store)[request.request_id] == result
    assert clock_calls == writes == 1
    assert not locked


@pytest.mark.parametrize(
    "status", [ApprovalStatus.REJECTED, ApprovalStatus.CONSUMED, ApprovalStatus.EXPIRED]
)
def test_terminal_requests_remain_unchanged_after_expiry(
    isolated_approval_store, monkeypatch, transition, status
):
    request = _create_request(approval.approve_request)
    if status == ApprovalStatus.REJECTED:
        approval.reject_request(request.request_id, now=CREATED_AT)
    elif status == ApprovalStatus.CONSUMED:
        approval.approve_request(request.request_id, now=CREATED_AT)
        approval.consume_request(request.request_id, now=CREATED_AT)
    else:
        _assert_expired(
            approval.approve_request, request.request_id, now=request.expires_at
        )
    before = isolated_approval_store.read_bytes()
    monkeypatch.setattr(
        approval, "_now", lambda: request.expires_at + timedelta(days=1)
    )

    if transition is approval.consume_request:
        assert transition(request.request_id) is None
    else:
        with pytest.raises(ValueError):
            transition(request.request_id)

    assert isolated_approval_store.read_bytes() == before


@pytest.mark.parametrize("explicit_now", [False, True], ids=["normal", "explicit"])
@pytest.mark.parametrize("approved", [False, True], ids=["pending", "approved"])
def test_lazy_expiry_preserves_caller_clock_choice(
    isolated_approval_store, monkeypatch, explicit_now, approved
):
    request = _create_request(
        approval.consume_request if approved else approval.approve_request
    )
    current = request.expires_at
    in_lock_time = current + timedelta(seconds=30)
    lock = approval._store_lock

    @contextmanager
    def delayed_lock(path):
        nonlocal current
        with lock(path):
            current = in_lock_time
            yield

    monkeypatch.setattr(approval, "_store_lock", delayed_lock)
    monkeypatch.setattr(
        approval, "_now", _unexpected_clock if explicit_now else lambda: current
    )
    kwargs = {"now": request.expires_at} if explicit_now else {}

    result = approval.get_request(request.request_id, **kwargs)

    assert result.status == ApprovalStatus.EXPIRED
    persisted = approval._read_store(isolated_approval_store)[request.request_id]
    assert persisted == request.model_copy(
        update={
            "status": ApprovalStatus.EXPIRED,
            "decided_at": request.expires_at if explicit_now else in_lock_time,
        }
    )


@pytest.mark.parametrize("stage", ["_now", "_read_store", "_write_store"])
@pytest.mark.parametrize(
    "error_type",
    [approval.ApprovalStoreError, MemoryError, KeyboardInterrupt, SystemExit],
)
def test_transition_failure_propagates_and_releases_lock(
    isolated_approval_store, monkeypatch, stage, error_type
):
    request = _create_request(approval.approve_request)
    before = isolated_approval_store.read_bytes()
    error = error_type("transition failure")

    def fail(*_args, **_kwargs):
        raise error

    with monkeypatch.context() as patched:
        patched.setattr(approval, "_now", lambda: request.expires_at)
        patched.setattr(approval, stage, fail)
        with pytest.raises(error_type) as captured:
            approval.approve_request(request.request_id)

    assert captured.value is error
    assert isolated_approval_store.read_bytes() == before
    with approval._store_lock(isolated_approval_store):
        pass
