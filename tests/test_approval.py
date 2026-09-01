"""Unit tests for the approval engine itself."""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.risk import RiskLevel


def _create_request(**kwargs):
    defaults = {
        "program": "python",
        "args": ["--version"],
        "cwd": ".",
        "risk": RiskLevel.MEDIUM,
        "risk_reason": "test",
    }
    defaults.update(kwargs)
    return approval.create_request(**defaults)


def _concurrent_create_request(
    store_path: str,
    start_event,
    result_queue,
    max_records: int,
    max_bytes: int,
) -> None:
    """Spawn-safe contender used to prove the cross-process quota lock."""
    approval.MAX_APPROVAL_RECORDS = max_records
    approval.MAX_APPROVAL_STORE_BYTES = max_bytes
    start_event.wait()
    try:
        request = approval.create_request(
            program="python",
            args=["--version"],
            cwd=".",
            risk=RiskLevel.MEDIUM,
            risk_reason="concurrency test",
            store_path=Path(store_path),
        )
    except approval.ApprovalStoreCapacityError as exc:
        result_queue.put(("capacity", exc.dimension))
    except Exception as exc:  # noqa: BLE001 - report child failures to the parent
        result_queue.put(("error", type(exc).__name__))
    else:
        result_queue.put(("created", request.request_id))


def _wait_for_store_lock(store_path: str, ready_event, entered_event) -> None:
    """Spawn-safe waiter used to prove lock serialization."""
    ready_event.set()
    with approval._store_lock(Path(store_path)):
        entered_event.set()


def _contend_for_store_lock(
    store_path: str,
    ready_event,
    result_queue,
    timeout_seconds: float,
) -> None:
    """Spawn-safe contender used to prove bounded timeout behavior."""
    approval.LOCK_TIMEOUT_SECONDS = timeout_seconds
    ready_event.set()
    try:
        with approval._store_lock(Path(store_path)):
            pass
    except TimeoutError:
        result_queue.put(("timeout", "TimeoutError"))
    except Exception as exc:  # noqa: BLE001 - report child failures to the parent
        result_queue.put(("error", type(exc).__name__))
    else:
        result_queue.put(("acquired", None))


def _hold_store_lock(store_path: str, held_event, release_event) -> None:
    """Spawn-safe owner used to prove process teardown releases the OS lock."""
    with approval._store_lock(Path(store_path)):
        held_event.set()
        release_event.wait(timeout=30)


def test_request_ids_are_cryptographically_random():
    first = _create_request()
    second = _create_request()

    assert first.request_id != second.request_id
    assert first.request_id.startswith("req_")
    assert len(first.request_id) > 16


def test_unknown_request_returns_none():
    assert approval.get_request("req_does_not_exist") is None


def test_approve_transitions_pending_to_approved():
    request = _create_request()

    approved = approval.approve_request(request.request_id)

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.decided_at is not None


def test_reject_transitions_pending_to_rejected():
    request = _create_request()

    rejected = approval.reject_request(request.request_id)

    assert rejected.status == ApprovalStatus.REJECTED


def test_approve_twice_fails():
    request = _create_request()
    approval.approve_request(request.request_id)

    with pytest.raises(ValueError):
        approval.approve_request(request.request_id)


def test_reject_unknown_request_fails():
    with pytest.raises(KeyError):
        approval.reject_request("req_does_not_exist")


def test_consume_is_single_use():
    request = _create_request()
    approval.approve_request(request.request_id)

    consumed = approval.consume_request(request.request_id)

    assert consumed is not None
    assert consumed.status == ApprovalStatus.CONSUMED
    assert approval.consume_request(request.request_id) is None


def test_expired_request_reported_expired():
    current = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    request = _create_request(ttl_seconds=0, now=current)

    fetched = approval.get_request(request.request_id, now=current)

    assert fetched.status == ApprovalStatus.EXPIRED


def test_expired_request_cannot_be_approved():
    current = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    request = _create_request(ttl_seconds=0, now=current)

    with pytest.raises(ValueError):
        approval.approve_request(request.request_id, now=current)


def test_store_is_persistent_json(isolated_approval_store):
    request = _create_request()

    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))

    assert raw["version"] == 2
    assert request.request_id in raw["requests"]
    assert raw["requests"][request.request_id]["status"] == "PENDING"
    assert raw["requests"][request.request_id]["trace_id"] == request.trace_id
    assert raw["requests"][request.request_id]["resume_tool"] == "shell.run_approved"


def test_record_capacity_allows_exact_limit_and_refuses_one_over_unchanged(
    isolated_approval_store,
    monkeypatch,
):
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 3)
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", 1_000_000)

    created = [_create_request() for _ in range(3)]
    before = isolated_approval_store.read_bytes()

    with pytest.raises(approval.ApprovalStoreCapacityError) as exc_info:
        _create_request(payload={"content": "must-not-be-persisted"})

    assert exc_info.value.dimension == "records"
    assert exc_info.value.resulting == 4
    assert exc_info.value.limit == 3
    assert isolated_approval_store.read_bytes() == before
    assert {item.request_id for item in approval.list_requests()} == {
        item.request_id for item in created
    }


def test_byte_capacity_allows_exact_limit_and_refuses_one_over(
    isolated_approval_store,
    temp_dir,
    monkeypatch,
):
    current = datetime(2026, 5, 1, tzinfo=UTC)
    request_id = "req_" + "a" * 32
    kwargs = {
        "payload": {"content": "bounded payload"},
        "trace_id": "trc_capacity_boundary",
        "now": current,
    }
    monkeypatch.setattr(approval, "_new_request_id", lambda: request_id)
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 10)
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", 1_000_000)

    probe_path = temp_dir / "probe.json"
    probe = _create_request(store_path=probe_path, **kwargs)
    assert probe_path.read_bytes() == approval._serialize_store(
        {probe.request_id: probe}
    )
    exact_size = len(probe_path.read_bytes())

    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", exact_size)
    exact_path = temp_dir / "exact.json"
    exact = _create_request(store_path=exact_path, **kwargs)
    assert exact.request_id == request_id
    assert len(exact_path.read_bytes()) == exact_size

    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", exact_size - 1)
    before = (
        isolated_approval_store.read_bytes()
        if isolated_approval_store.exists()
        else b""
    )
    with pytest.raises(approval.ApprovalStoreCapacityError) as exc_info:
        _create_request(**kwargs)

    assert exc_info.value.dimension == "bytes"
    assert exc_info.value.resulting == exact_size
    assert exc_info.value.limit == exact_size - 1
    assert (
        isolated_approval_store.read_bytes()
        if isolated_approval_store.exists()
        else b""
    ) == before


def test_byte_capacity_counts_utf8_bytes_not_python_characters(
    isolated_approval_store,
    temp_dir,
    monkeypatch,
):
    current = datetime(2026, 5, 1, tzinfo=UTC)
    kwargs = {
        "payload": {"content": "\u754c" * 20},
        "trace_id": "trc_utf8_capacity",
        "now": current,
    }
    monkeypatch.setattr(approval, "_new_request_id", lambda: "req_" + "b" * 32)
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 10)
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", 1_000_000)

    probe_path = temp_dir / "utf8-probe.json"
    _create_request(store_path=probe_path, **kwargs)
    serialized = probe_path.read_bytes()
    character_count = len(serialized.decode("utf-8"))
    assert character_count < len(serialized)

    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", character_count)
    with pytest.raises(approval.ApprovalStoreCapacityError) as exc_info:
        _create_request(**kwargs)

    assert exc_info.value.dimension == "bytes"
    assert exc_info.value.resulting == len(serialized)
    assert not isolated_approval_store.exists()


def test_capacity_exception_is_bounded_and_contains_no_protected_payload(
    monkeypatch,
):
    sentinel = "TOP-SECRET-CAPACITY-PAYLOAD-9f11"
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 0)

    with pytest.raises(approval.ApprovalStoreCapacityError) as exc_info:
        _create_request(
            program=sentinel,
            args=[sentinel],
            payload={"content": sentinel, "path": sentinel},
        )

    diagnostic = str(exc_info.value)
    assert sentinel not in diagnostic
    assert len(diagnostic) < 500
    assert "prune approvals" in diagnostic


def test_existing_oversized_store_refuses_additions_but_allows_transitions(
    isolated_approval_store,
    monkeypatch,
):
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 3)
    first, second, third = (_create_request() for _ in range(3))
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 2)
    before = isolated_approval_store.read_bytes()

    with pytest.raises(approval.ApprovalStoreCapacityError):
        _create_request()

    assert isolated_approval_store.read_bytes() == before
    assert approval.approve_request(first.request_id).status == ApprovalStatus.APPROVED
    assert approval.reject_request(second.request_id).status == ApprovalStatus.REJECTED
    assert approval.approve_request(third.request_id).status == ApprovalStatus.APPROVED
    assert approval.consume_request(third.request_id).status == ApprovalStatus.CONSUMED
    assert len(approval.list_requests()) == 3


def test_existing_byte_oversized_store_refuses_additions_but_allows_transition(
    isolated_approval_store,
    monkeypatch,
):
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", 1_000_000)
    request = _create_request(payload={"content": "bounded"})
    before = isolated_approval_store.read_bytes()
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", len(before) - 1)

    with pytest.raises(approval.ApprovalStoreCapacityError) as exc_info:
        _create_request()

    assert exc_info.value.dimension == "bytes"
    assert isolated_approval_store.read_bytes() == before
    assert (
        approval.approve_request(request.request_id).status == ApprovalStatus.APPROVED
    )


def test_oversized_store_can_be_pruned_and_capacity_recovered(
    isolated_approval_store,
    monkeypatch,
):
    current = datetime(2026, 5, 20, tzinfo=UTC)
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 2)
    requests = [_create_request(now=current - timedelta(days=30)) for _ in range(2)]
    for request in requests:
        approval.reject_request(
            request.request_id,
            now=current - timedelta(days=30) + timedelta(minutes=1),
        )
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", 1)
    before = isolated_approval_store.read_bytes()

    dry_run = approval.prune_requests(10, now=current)
    assert dry_run.eligible == 2
    assert isolated_approval_store.read_bytes() == before

    applied = approval.prune_requests(10, apply=True, now=current)
    assert applied.changed is True
    assert applied.retained == 0
    assert _create_request(now=current).status == ApprovalStatus.PENDING


def test_create_request_keeps_malformed_store_unchanged(isolated_approval_store):
    malformed = b'{"version":2,"requests":['
    isolated_approval_store.write_bytes(malformed)

    with pytest.raises(approval.ApprovalStoreError):
        _create_request()

    assert isolated_approval_store.read_bytes() == malformed


def test_concurrent_process_creators_cannot_exceed_record_capacity(
    isolated_approval_store,
    monkeypatch,
):
    max_records = 3
    max_bytes = 1_000_000
    monkeypatch.setattr(approval, "MAX_APPROVAL_RECORDS", max_records)
    monkeypatch.setattr(approval, "MAX_APPROVAL_STORE_BYTES", max_bytes)
    existing = [_create_request() for _ in range(max_records - 1)]

    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_concurrent_create_request,
            args=(
                str(isolated_approval_store),
                start_event,
                result_queue,
                max_records,
                max_bytes,
            ),
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    results = [result_queue.get(timeout=5) for _ in processes]
    created = [value for outcome, value in results if outcome == "created"]
    refused = [value for outcome, value in results if outcome == "capacity"]
    errors = [value for outcome, value in results if outcome == "error"]
    assert len(created) == 1
    assert refused == ["records"] * 3
    assert errors == []

    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))
    final_ids = set(raw["requests"])
    persisted_request_ids = [
        record["request_id"] for record in raw["requests"].values()
    ]
    assert len(final_ids) == max_records
    assert {request.request_id for request in existing} <= final_ids
    assert created[0] in final_ids
    assert len(persisted_request_ids) == len(set(persisted_request_ids))
    assert set(persisted_request_ids) == final_ids
    assert len(isolated_approval_store.read_bytes()) <= max_bytes


def test_store_lock_serializes_processes_and_keeps_stable_sidecar(
    isolated_approval_store,
):
    context = multiprocessing.get_context("spawn")
    ready_event = context.Event()
    entered_event = context.Event()
    process = context.Process(
        target=_wait_for_store_lock,
        args=(str(isolated_approval_store), ready_event, entered_event),
    )
    lock_path = isolated_approval_store.with_name(
        isolated_approval_store.name + ".lock"
    )

    try:
        with approval._store_lock(isolated_approval_store):
            process.start()
            assert ready_event.wait(timeout=10)
            assert entered_event.wait(timeout=0.25) is False

        assert entered_event.wait(timeout=10)
        process.join(timeout=10)
        assert process.exitcode == 0
        assert lock_path.exists()

        with approval._store_lock(isolated_approval_store):
            assert lock_path.exists()
        assert lock_path.exists()
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_store_lock_contention_times_out_without_permission_error(
    isolated_approval_store,
):
    context = multiprocessing.get_context("spawn")
    ready_event = context.Event()
    result_queue = context.Queue()
    process = context.Process(
        target=_contend_for_store_lock,
        args=(str(isolated_approval_store), ready_event, result_queue, 0.2),
    )

    try:
        with approval._store_lock(isolated_approval_store):
            process.start()
            assert ready_event.wait(timeout=10)
            process.join(timeout=10)
            assert process.exitcode == 0
            assert result_queue.get(timeout=5) == ("timeout", "TimeoutError")

        with approval._store_lock(isolated_approval_store):
            pass
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_store_lock_is_released_when_owner_process_terminates(
    isolated_approval_store,
    monkeypatch,
):
    context = multiprocessing.get_context("spawn")
    held_event = context.Event()
    release_event = context.Event()
    process = context.Process(
        target=_hold_store_lock,
        args=(str(isolated_approval_store), held_event, release_event),
    )
    process.start()

    try:
        assert held_event.wait(timeout=10)
        process.terminate()
        process.join(timeout=10)
        assert process.exitcode != 0
        assert isolated_approval_store.with_name(
            isolated_approval_store.name + ".lock"
        ).exists()

        monkeypatch.setattr(approval, "LOCK_TIMEOUT_SECONDS", 0.5)
        with approval._store_lock(isolated_approval_store):
            pass
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_store_lock_wraps_sidecar_permission_failure(
    isolated_approval_store,
    monkeypatch,
):
    original_open = os.open

    def deny_open(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "access denied")

    def unexpected_retry(_seconds):
        raise AssertionError("sidecar permission failures must not be retried")

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(approval.os, "open", deny_open)
        scoped_monkeypatch.setattr(approval.time, "sleep", unexpected_retry)

        with (
            pytest.raises(approval.ApprovalStoreError) as captured,
            approval._store_lock(isolated_approval_store),
        ):
            pass

    assert isinstance(captured.value.__cause__, PermissionError)
    assert os.open is original_open


def test_store_lock_propagates_non_contention_lock_error(
    isolated_approval_store,
    monkeypatch,
):
    def fail_lock(_descriptor):
        raise OSError(errno.EIO, "lock I/O failure")

    def unexpected_retry(_seconds):
        raise AssertionError("non-contention lock failures must not be retried")

    monkeypatch.setattr(approval, "_acquire_os_lock", fail_lock)
    monkeypatch.setattr(approval.time, "sleep", unexpected_retry)

    with (
        pytest.raises(OSError) as exc_info,
        approval._store_lock(isolated_approval_store),
    ):
        pass

    assert exc_info.value.errno == errno.EIO


def test_version_one_store_is_read_with_derived_contract_metadata(
    isolated_approval_store,
):
    request = _create_request(payload={"trace_id": "trc_existing_v1"})
    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))
    record = raw["requests"][request.request_id]
    record.pop("trace_id")
    record.pop("resume_tool")
    raw["version"] = 1
    isolated_approval_store.write_text(json.dumps(raw), encoding="utf-8")

    loaded = approval.get_request(request.request_id)

    assert loaded.trace_id == "trc_existing_v1"
    assert loaded.resume_tool == "shell.run_approved"


def test_version_one_derived_traces_are_deterministic_and_request_unique(
    isolated_approval_store,
):
    first = _create_request(payload={})
    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))
    first_record = raw["requests"][first.request_id]
    first_record.pop("trace_id")
    first_record.pop("resume_tool")

    second_id = "req_" + "2" * 32
    second_record = json.loads(json.dumps(first_record))
    second_record["request_id"] = second_id
    raw["version"] = 1
    raw["requests"] = {
        first.request_id: first_record,
        second_id: second_record,
    }
    isolated_approval_store.write_text(json.dumps(raw), encoding="utf-8")

    first_trace = approval.get_request(first.request_id).trace_id
    repeated_trace = approval.get_request(first.request_id).trace_id
    second_trace = approval.get_request(second_id).trace_id

    assert first_trace == repeated_trace
    assert first_trace != second_trace
    assert first_trace != first.request_id
    assert second_trace != second_id


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        json.dumps({"version": 99, "requests": {}}),
        json.dumps({"version": 2, "requests": []}),
    ],
)
def test_malformed_or_incompatible_store_is_not_silently_accepted(
    isolated_approval_store,
    payload,
):
    isolated_approval_store.write_text(payload, encoding="utf-8")

    with pytest.raises(approval.ApprovalStoreError):
        approval.get_request("req_unknown")


def test_stored_resume_tool_cannot_be_tampered_with(isolated_approval_store):
    request = _create_request()
    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))
    raw["requests"][request.request_id]["resume_tool"] = "shell.evil"
    isolated_approval_store.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(approval.ApprovalStoreError):
        approval.get_request(request.request_id)


def test_prune_dry_run_does_not_mutate_store(isolated_approval_store):
    current = datetime(2026, 4, 20, tzinfo=UTC)
    request = _create_request(now=current - timedelta(days=20))
    approval.reject_request(
        request.request_id,
        now=current - timedelta(days=20) + timedelta(minutes=1),
    )
    before = isolated_approval_store.read_bytes()

    result = approval.prune_requests(10, now=current)

    assert result.eligible == 1
    assert result.changed is False
    assert isolated_approval_store.read_bytes() == before


def test_prune_apply_removes_old_rejected_consumed_and_persisted_expired():
    current = datetime(2026, 4, 20, tzinfo=UTC)

    rejected = _create_request(now=current - timedelta(days=30))
    approval.reject_request(
        rejected.request_id,
        now=current - timedelta(days=30) + timedelta(minutes=1),
    )

    consumed = _create_request(now=current - timedelta(days=28))
    approval.approve_request(
        consumed.request_id,
        now=current - timedelta(days=28) + timedelta(minutes=1),
    )
    approval.consume_request(
        consumed.request_id,
        now=current - timedelta(days=28) + timedelta(minutes=2),
    )

    expired = _create_request(ttl_seconds=0, now=current - timedelta(days=25))
    approval.get_request(expired.request_id, now=current - timedelta(days=24))

    result = approval.prune_requests(10, apply=True, now=current)

    assert result.changed is True
    assert result.eligible == 3
    assert result.eligible_by_status == {
        ApprovalStatus.REJECTED: 1,
        ApprovalStatus.EXPIRED: 1,
        ApprovalStatus.CONSUMED: 1,
    }
    assert approval.list_requests(now=current) == []


@pytest.mark.parametrize("approve", [False, True], ids=["pending", "approved"])
def test_prune_apply_removes_effectively_expired_active_states(approve):
    current = datetime(2026, 4, 20, tzinfo=UTC)
    created = current - timedelta(days=30)
    request = _create_request(ttl_seconds=60, now=created)
    if approve:
        approval.approve_request(request.request_id, now=created)

    result = approval.prune_requests(10, apply=True, now=current)

    assert result.eligible_by_status[ApprovalStatus.EXPIRED] == 1
    assert approval.get_request(request.request_id, now=current) is None


def test_prune_retains_valid_active_and_recent_terminal_requests():
    current = datetime(2026, 4, 20, tzinfo=UTC)
    pending = _create_request(ttl_seconds=86_400, now=current)
    approved = _create_request(ttl_seconds=86_400, now=current)
    approval.approve_request(approved.request_id, now=current)
    recent_rejected = _create_request(now=current - timedelta(days=2))
    approval.reject_request(
        recent_rejected.request_id,
        now=current - timedelta(days=2) + timedelta(minutes=1),
    )

    result = approval.prune_requests(10, apply=True, now=current)

    assert result.eligible == 0
    assert result.changed is False
    assert {item.request_id for item in approval.list_requests(now=current)} == {
        pending.request_id,
        approved.request_id,
        recent_rejected.request_id,
    }


def test_prune_cutoff_is_inclusive():
    current = datetime(2026, 4, 20, 12, tzinfo=UTC)
    request = _create_request(now=current - timedelta(days=10) - timedelta(minutes=1))
    approval.reject_request(request.request_id, now=current - timedelta(days=10))

    result = approval.prune_requests(10, apply=True, now=current)

    assert result.cutoff == current - timedelta(days=10)
    assert result.eligible == 1
    assert approval.get_request(request.request_id) is None


def test_prune_malformed_store_fails_closed(isolated_approval_store):
    malformed = b'{"version":2,"requests":['
    isolated_approval_store.write_bytes(malformed)

    with pytest.raises(approval.ApprovalStoreError):
        approval.prune_requests(0, apply=True)

    assert isolated_approval_store.read_bytes() == malformed


@pytest.mark.parametrize("older_than_days", [-1, 10**20])
def test_prune_invalid_age_does_not_mutate_store(
    isolated_approval_store,
    older_than_days,
):
    _create_request()
    before = isolated_approval_store.read_bytes()

    with pytest.raises(ValueError):
        approval.prune_requests(older_than_days, apply=True)

    assert isolated_approval_store.read_bytes() == before


def test_prune_apply_recomputes_after_lazy_expiry_is_persisted():
    current = datetime(2026, 4, 20, tzinfo=UTC)
    request = _create_request(ttl_seconds=0, now=current - timedelta(days=20))

    dry_run = approval.prune_requests(10, now=current)
    assert dry_run.eligible == 1

    persisted = approval.get_request(request.request_id, now=current)
    assert persisted.status == ApprovalStatus.EXPIRED

    applied = approval.prune_requests(10, apply=True, now=current)

    assert applied.eligible == 0
    assert applied.changed is False
    assert approval.get_request(request.request_id, now=current) is not None
