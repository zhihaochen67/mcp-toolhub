"""Unit tests for the approval engine itself."""

from __future__ import annotations

import json
from datetime import UTC, datetime

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
