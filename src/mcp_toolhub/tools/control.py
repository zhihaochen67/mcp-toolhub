"""Read-only MCP surfaces for Contract V1 discovery and request observation."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from mcp_toolhub import __version__
from mcp_toolhub.contracts import (
    APPROVAL_TOOL_PAIRS,
    CONTRACT_VERSION,
    ApprovalModelSummary,
    ApprovalOperationMapping,
    ApprovalStatus,
    CapabilitiesResult,
    ContractOutcome,
    PublicLimits,
    RequestStatusResult,
    make_contract_error,
    outcome_for_approval_status,
)
from mcp_toolhub.observability import audit
from mcp_toolhub.observability.audit import MAX_READ_EVENTS
from mcp_toolhub.security import approval
from mcp_toolhub.security.paths import MAX_FILE_SIZE
from mcp_toolhub.tools.filesystem import MAX_PATCH_CHARS, MAX_WRITE_BYTES
from mcp_toolhub.tools.git import GIT_MAX_OUTPUT_CHARS
from mcp_toolhub.tools.shell import MAX_OUTPUT_CHARS, MAX_TIMEOUT_SECONDS

CONTROL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    open_world_hint=False,
)


def capabilities() -> CapabilitiesResult:
    """Return deterministic public Contract V1 capabilities and limits."""
    operations = [
        ApprovalOperationMapping(initial_tool=initial, resume_tool=resume)
        for _kind, initial, resume in APPROVAL_TOOL_PAIRS
    ]
    return CapabilitiesResult(
        contract_version=CONTRACT_VERSION,
        package_version=__version__,
        transport="stdio",
        approval_model=ApprovalModelSummary(),
        approval_operations=operations,
        limits=PublicLimits(
            max_read_file_bytes=MAX_FILE_SIZE,
            max_write_bytes=MAX_WRITE_BYTES,
            max_patch_chars=MAX_PATCH_CHARS,
            max_shell_timeout_seconds=MAX_TIMEOUT_SECONDS,
            shell_output_retained_chars=MAX_OUTPUT_CHARS,
            git_output_retained_chars=GIT_MAX_OUTPUT_CHARS,
            max_audit_events=MAX_READ_EVENTS,
        ),
    )


def request_status(request_id: str) -> RequestStatusResult:
    """Observe an approval request without changing or consuming its state."""
    request = approval.observe_request(request_id)
    if request is None:
        return RequestStatusResult(
            request_id=request_id,
            outcome=ContractOutcome.REFUSED,
            trace_id=audit.new_trace_id(),
            error=make_contract_error(
                "REQUEST_NOT_FOUND",
                "Approval request is unavailable.",
            ),
        )

    error = None
    if request.status == ApprovalStatus.PENDING:
        error = make_contract_error(
            "APPROVAL_PENDING",
            "Approval request is pending human review.",
            retryable=True,
        )
    elif request.status == ApprovalStatus.REJECTED:
        error = make_contract_error(
            "APPROVAL_REJECTED",
            "Approval request was rejected.",
        )
    elif request.status == ApprovalStatus.EXPIRED:
        error = make_contract_error(
            "APPROVAL_EXPIRED",
            "Approval request expired.",
        )
    elif request.status == ApprovalStatus.CONSUMED:
        error = make_contract_error(
            "APPROVAL_CONSUMED",
            "Approval request has already been consumed.",
        )

    return RequestStatusResult(
        request_id=request.request_id,
        outcome=outcome_for_approval_status(request.status),
        trace_id=request.trace_id,
        approval=request.public_handle(),
        error=error,
    )


def register_control_tools(mcp: MCPServer) -> None:
    """Register the strictly read-only Contract V1 control tools."""

    @mcp.tool(
        name="toolhub.capabilities",
        title="Show ToolHub capabilities",
        annotations=CONTROL_ANNOTATIONS,
    )
    def _capabilities() -> CapabilitiesResult:
        """Return the versioned public ToolHub execution contract."""
        return capabilities()

    @mcp.tool(
        name="toolhub.request_status",
        title="Show approval request status",
        annotations=CONTROL_ANNOTATIONS,
    )
    def _request_status(request_id: str) -> RequestStatusResult:
        """Observe an approval request without approving, rejecting, or consuming it."""
        return request_status(request_id)
