"""Unit tests for the approval engine itself."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

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
