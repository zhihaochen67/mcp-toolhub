"""Unit tests for the approval engine itself."""

from __future__ import annotations

import json

import pytest

from toolhub.security import approval
from toolhub.security.approval import ApprovalStatus
from toolhub.security.risk import RiskLevel


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
    request = _create_request(ttl_seconds=0)

    fetched = approval.get_request(request.request_id)

    assert fetched.status == ApprovalStatus.EXPIRED


def test_expired_request_cannot_be_approved():
    request = _create_request(ttl_seconds=0)

    with pytest.raises(ValueError):
        approval.approve_request(request.request_id)


def test_store_is_persistent_json(isolated_approval_store):
    request = _create_request()

    raw = json.loads(isolated_approval_store.read_text(encoding="utf-8"))

    assert raw["version"] == 1
    assert request.request_id in raw["requests"]
    assert raw["requests"][request.request_id]["status"] == "PENDING"
