"""Versioned public lifecycle contract for agent-facing ToolHub operations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.0"
MAX_CONTRACT_ERROR_CHARS = 500


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ContractOutcome(str, Enum):
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    SUCCEEDED = "SUCCEEDED"
    COMMAND_FAILED = "COMMAND_FAILED"
    TIMED_OUT = "TIMED_OUT"
    CONFLICT = "CONFLICT"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class ContractError(_ContractModel):
    code: str = Field(min_length=1, max_length=80, pattern=r"^[A-Z][A-Z0-9_]*$")
    message: str = Field(max_length=MAX_CONTRACT_ERROR_CHARS)
    retryable: bool


class ApprovalHandle(_ContractModel):
    request_id: str
    status: ApprovalStatus
    expires_at: datetime
    resume_tool: str


class ContractLifecycle(_ContractModel):
    outcome: ContractOutcome
    trace_id: str
    approval: ApprovalHandle | None = None
    error: ContractError | None = None


class ApprovalOperationMapping(_ContractModel):
    initial_tool: str
    resume_tool: str


class ApprovalModelSummary(_ContractModel):
    human_only: bool = True
    out_of_band: bool = True
    atomic: bool = True
    single_use: bool = True
    expiring: bool = True
    status_tool: str = "toolhub.request_status"


class PublicLimits(_ContractModel):
    max_read_file_bytes: int
    max_write_bytes: int
    max_patch_chars: int
    max_shell_timeout_seconds: int
    shell_output_retained_chars: int
    git_output_retained_chars: int
    max_audit_events: int


class CapabilitiesResult(_ContractModel):
    contract_version: str
    package_version: str
    transport: Literal["stdio"]
    approval_model: ApprovalModelSummary
    approval_operations: list[ApprovalOperationMapping]
    limits: PublicLimits


class RequestStatusResult(ContractLifecycle):
    request_id: str


APPROVAL_TOOL_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("file_patch", "filesystem.apply_patch", "filesystem.apply_patch_approved"),
    ("file_write", "filesystem.write_file", "filesystem.write_file_approved"),
    ("shell", "shell.run", "shell.run_approved"),
)

_RESUME_TOOL_BY_KIND = {
    kind: resume_tool for kind, _initial_tool, resume_tool in APPROVAL_TOOL_PAIRS
}


def resume_tool_for_kind(kind: str) -> str:
    try:
        return _RESUME_TOOL_BY_KIND[kind]
    except KeyError as exc:
        raise ValueError(f"Unsupported approval request kind: {kind}") from exc


def make_contract_error(
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> ContractError:
    bounded = str(message)[:MAX_CONTRACT_ERROR_CHARS]
    return ContractError(code=code, message=bounded, retryable=retryable)


def outcome_for_approval_status(status: ApprovalStatus) -> ContractOutcome:
    return {
        ApprovalStatus.PENDING: ContractOutcome.APPROVAL_PENDING,
        ApprovalStatus.APPROVED: ContractOutcome.APPROVAL_APPROVED,
        ApprovalStatus.REJECTED: ContractOutcome.APPROVAL_REJECTED,
        ApprovalStatus.EXPIRED: ContractOutcome.APPROVAL_EXPIRED,
        ApprovalStatus.CONSUMED: ContractOutcome.APPROVAL_CONSUMED,
    }[status]
