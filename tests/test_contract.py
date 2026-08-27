"""Contract V1 lifecycle, discovery, and compatibility coverage."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_toolhub import __version__
from mcp_toolhub.app import create_server
from mcp_toolhub.contracts import (
    APPROVAL_TOOL_PAIRS,
    CONTRACT_VERSION,
    MAX_CONTRACT_ERROR_CHARS,
    ApprovalHandle,
    ApprovalStatus,
    ContractError,
    ContractOutcome,
    make_contract_error,
)
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.paths import get_workspace_root
from mcp_toolhub.security.risk import RiskLevel
from mcp_toolhub.tools.control import capabilities, request_status
from mcp_toolhub.tools.filesystem import write_file, write_file_approved
from mcp_toolhub.tools.git import GIT_MAX_OUTPUT_CHARS
from mcp_toolhub.tools.git import _truncate as _truncate_git_output
from mcp_toolhub.tools.shell import (
    MAX_OUTPUT_CHARS,
    _truncate_output,
    run_approved_shell,
    run_shell,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "contract_v1.json"


def _request(*, kind: str = "shell", **kwargs):
    defaults = {
        "kind": kind,
        "risk": RiskLevel.MEDIUM,
        "risk_reason": "contract test",
        "payload": {"workspace_root": str(get_workspace_root())},
    }
    defaults.update(kwargs)
    return approval.create_request(**defaults)


def _strip_schema_noise(value):
    if isinstance(value, dict):
        return {
            key: _strip_schema_noise(item)
            for key, item in sorted(value.items())
            if key not in {"description", "title"}
        }
    if isinstance(value, list):
        return [_strip_schema_noise(item) for item in value]
    return value


def _schema_contract(schema: dict) -> dict:
    """Keep an auditable shape plus an exact digest of the normalized schema."""
    normalized = _strip_schema_noise(schema)
    encoded = json.dumps(
        normalized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "properties": sorted(normalized.get("properties", {})),
        "required": normalized.get("required", []),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


async def _contract_surface() -> dict:
    tools = await create_server().list_tools()
    public_tools = {}
    for tool in sorted(tools, key=lambda item: item.name):
        annotations = tool.annotations
        public_tools[tool.name] = {
            "annotations": {
                "destructive_hint": (
                    annotations.destructive_hint if annotations is not None else None
                ),
                "idempotent_hint": (
                    annotations.idempotent_hint if annotations is not None else None
                ),
                "open_world_hint": (
                    annotations.open_world_hint if annotations is not None else None
                ),
                "read_only_hint": (
                    annotations.read_only_hint if annotations is not None else None
                ),
            },
            "input_schema": _schema_contract(tool.input_schema),
            "output_schema": _schema_contract(tool.output_schema or {}),
        }

    return {
        "approval_operations": [
            {"initial_tool": initial, "resume_tool": resume}
            for _kind, initial, resume in APPROVAL_TOOL_PAIRS
        ],
        "approval_statuses": [status.value for status in ApprovalStatus],
        "contract_version": CONTRACT_VERSION,
        "outcomes": [outcome.value for outcome in ContractOutcome],
        "tools": public_tools,
    }


def test_contract_version_is_independent_of_package_version():
    assert CONTRACT_VERSION == "1.0"
    assert CONTRACT_VERSION != __version__


def test_stable_contract_outcomes_are_exact():
    assert [outcome.value for outcome in ContractOutcome] == [
        "APPROVAL_REQUIRED",
        "APPROVAL_PENDING",
        "APPROVAL_APPROVED",
        "APPROVAL_REJECTED",
        "APPROVAL_EXPIRED",
        "APPROVAL_CONSUMED",
        "SUCCEEDED",
        "COMMAND_FAILED",
        "TIMED_OUT",
        "CONFLICT",
        "REFUSED",
        "FAILED",
    ]


def test_error_and_approval_handle_shapes():
    error = ContractError(code="TEST_ERROR", message="bounded", retryable=True)
    request = _request()
    handle = request.public_handle()

    assert error.model_dump() == {
        "code": "TEST_ERROR",
        "message": "bounded",
        "retryable": True,
    }
    assert isinstance(handle, ApprovalHandle)
    assert handle.model_dump() == {
        "request_id": request.request_id,
        "status": ApprovalStatus.PENDING,
        "expires_at": request.expires_at,
        "resume_tool": "shell.run_approved",
    }


def test_contract_error_messages_are_bounded():
    error = make_contract_error("BOUNDED", "x" * 10_000)
    assert len(error.message) == MAX_CONTRACT_ERROR_CHARS


def test_capabilities_are_deterministic_and_public():
    first = capabilities()
    second = capabilities()

    assert first == second
    assert first.contract_version == "1.0"
    assert first.package_version == __version__
    assert first.transport == "stdio"
    assert first.approval_model.human_only is True
    assert [item.model_dump() for item in first.approval_operations] == [
        {"initial_tool": initial, "resume_tool": resume}
        for _kind, initial, resume in APPROVAL_TOOL_PAIRS
    ]
    serialized = first.model_dump_json()
    for forbidden in ("workspace-binding.json", "approvals.json", "audit.jsonl"):
        assert forbidden not in serialized


def test_capability_output_retention_limits_match_implementations():
    limits = capabilities().limits

    assert limits.shell_output_retained_chars == MAX_OUTPUT_CHARS
    assert limits.git_output_retained_chars == GIT_MAX_OUTPUT_CHARS

    shell_source = "s" * (limits.shell_output_retained_chars + 17)
    shell_output = _truncate_output(shell_source)
    assert shell_output[: limits.shell_output_retained_chars] == (
        "s" * limits.shell_output_retained_chars
    )
    assert shell_output[limits.shell_output_retained_chars :] == (
        "\n\n[ToolHub truncated 17 characters]"
    )

    git_source = "g" * (limits.git_output_retained_chars + 19)
    git_output = _truncate_git_output(git_source)
    assert git_output[: limits.git_output_retained_chars] == (
        "g" * limits.git_output_retained_chars
    )
    assert git_output[limits.git_output_retained_chars :] == (
        "\n...[+19 chars truncated]"
    )


@pytest.mark.parametrize(
    ("kind", "resume_tool"),
    [
        ("shell", "shell.run_approved"),
        ("file_write", "filesystem.write_file_approved"),
        ("file_patch", "filesystem.apply_patch_approved"),
    ],
)
def test_resume_tool_is_server_derived(kind, resume_tool):
    request = _request(kind=kind)
    assert request.resume_tool == resume_tool
    assert request_status(request.request_id).approval.resume_tool == resume_tool


def test_request_status_observes_all_states_without_consuming():
    pending = _request()
    pending_status = request_status(pending.request_id)
    assert pending_status.outcome == ContractOutcome.APPROVAL_PENDING
    assert pending_status.approval.status == ApprovalStatus.PENDING
    assert pending_status.error.code == "APPROVAL_PENDING"
    assert approval.get_request(pending.request_id).status == ApprovalStatus.PENDING

    approval.approve_request(pending.request_id)
    approved_status = request_status(pending.request_id)
    assert approved_status.outcome == ContractOutcome.APPROVAL_APPROVED
    assert approved_status.error is None
    assert approval.get_request(pending.request_id).status == ApprovalStatus.APPROVED

    approval.consume_request(pending.request_id)
    consumed_status = request_status(pending.request_id)
    assert consumed_status.outcome == ContractOutcome.APPROVAL_CONSUMED
    assert consumed_status.error.code == "APPROVAL_CONSUMED"

    rejected = _request()
    approval.reject_request(rejected.request_id)
    rejected_status = request_status(rejected.request_id)
    assert rejected_status.outcome == ContractOutcome.APPROVAL_REJECTED
    assert rejected_status.error.code == "APPROVAL_REJECTED"


def test_request_status_observes_expiry_without_mutating_store(isolated_approval_store):
    current = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    request = _request(ttl_seconds=0, now=current)
    before = isolated_approval_store.read_bytes()

    status = request_status(request.request_id)

    assert status.outcome == ContractOutcome.APPROVAL_EXPIRED
    assert status.approval.status == ApprovalStatus.EXPIRED
    assert isolated_approval_store.read_bytes() == before


def test_unknown_and_other_store_requests_are_indistinguishable(temp_dir):
    other_store = temp_dir / "other-approvals.json"
    other = approval.create_request(
        risk=RiskLevel.HIGH,
        risk_reason="other workspace",
        store_path=other_store,
    )

    other_result = request_status(other.request_id)
    unknown_result = request_status("req_" + "0" * 32)

    assert other_result.outcome == unknown_result.outcome == ContractOutcome.REFUSED
    assert other_result.approval is unknown_result.approval is None
    assert other_result.error == unknown_result.error
    assert other_result.error.code == "REQUEST_NOT_FOUND"


def test_request_status_never_exposes_protected_payload():
    sentinel_values = {
        "content": "TOP-SECRET-CONTENT-1d3a",
        "patch": "TOP-SECRET-PATCH-6c22",
        "args": "TOP-SECRET-ARGUMENT-8f31",
        "executable": "C:/private/tool.exe",
        "state": "C:/private/toolhub-state",
    }
    request = _request(
        payload={**sentinel_values, "workspace_root": str(get_workspace_root())}
    )

    serialized = request_status(request.request_id).model_dump_json()
    assert all(value not in serialized for value in sentinel_values.values())


def test_write_lifecycle_trace_continuity_and_consumed_replay(temp_dir):
    created = write_file("trace.txt", "hello", root=temp_dir)
    pending = request_status(created.request_id)
    approval.approve_request(created.request_id)
    approved = request_status(created.request_id)
    executed = write_file_approved(created.request_id, root=temp_dir)
    consumed = request_status(created.request_id)
    replay = write_file_approved(created.request_id, root=temp_dir)

    assert {
        created.trace_id,
        pending.trace_id,
        approved.trace_id,
        executed.trace_id,
        consumed.trace_id,
        replay.trace_id,
    } == {created.trace_id}
    assert created.outcome == ContractOutcome.APPROVAL_REQUIRED
    assert executed.outcome == ContractOutcome.SUCCEEDED
    assert replay.outcome == ContractOutcome.APPROVAL_CONSUMED
    related = [
        event
        for event in audit.read_recent(limit=100)
        if event.get("request_id") == created.request_id
    ]
    assert {event["trace_id"] for event in related} == {created.trace_id}


def test_shell_lifecycle_trace_continuity(high_python_command):
    program, args = high_python_command
    created = run_shell(program, args)
    pending = request_status(created.request_id)
    approval.approve_request(created.request_id)
    approved = request_status(created.request_id)
    executed = run_approved_shell(created.request_id)
    consumed = request_status(created.request_id)

    assert {
        created.trace_id,
        pending.trace_id,
        approved.trace_id,
        executed.trace_id,
        consumed.trace_id,
    } == {created.trace_id}
    assert executed.outcome == ContractOutcome.SUCCEEDED
    related = [
        event
        for event in audit.read_recent(limit=100)
        if event.get("request_id") == created.request_id
    ]
    assert {event["trace_id"] for event in related} == {created.trace_id}


def test_conflict_after_approval_is_structured_and_consumed(temp_dir):
    path = temp_dir / "conflict.txt"
    path.write_text("before", encoding="utf-8")
    digest = hashlib.sha256(b"before").hexdigest()
    created = write_file(
        "conflict.txt",
        "after",
        expected_hash=digest,
        root=temp_dir,
    )
    path.write_text("changed", encoding="utf-8")
    approval.approve_request(created.request_id)

    conflict = write_file_approved(created.request_id, root=temp_dir)
    replay = write_file_approved(created.request_id, root=temp_dir)

    assert conflict.outcome == ContractOutcome.CONFLICT
    assert conflict.error.code == "MUTATION_CONFLICT"
    assert (
        request_status(created.request_id).outcome == ContractOutcome.APPROVAL_CONSUMED
    )
    assert replay.outcome == ContractOutcome.APPROVAL_CONSUMED
    assert path.read_text(encoding="utf-8") == "changed"


def test_structured_content_is_primary_for_contract_tools():
    async def main():
        server = create_server()
        capability_result = await server.call_tool("toolhub.capabilities", {})
        assert capability_result.is_error is False
        assert capability_result.structured_content["contract_version"] == "1.0"

        status_result = await server.call_tool(
            "toolhub.request_status", {"request_id": "req_" + "0" * 32}
        )
        assert status_result.is_error is False
        assert status_result.structured_content["outcome"] == "REFUSED"
        assert status_result.structured_content["error"]["code"] == "REQUEST_NOT_FOUND"

    anyio.run(main)


def test_contract_v1_compatibility_fixture_matches_surface():
    expected = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    actual = anyio.run(_contract_surface)
    assert actual == expected
