import subprocess
import time
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from mcp_toolhub.contracts import (
    ApprovalHandle,
    ContractLifecycle,
    ContractOutcome,
    make_contract_error,
    outcome_for_approval_status,
)
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.command_policy import (
    CommandPolicyDecision,
    assess_shell_command,
)
from mcp_toolhub.security.executable_snapshot import (
    resolve_executable_snapshot,
    validate_executable_snapshot,
)
from mcp_toolhub.security.execution_environment import (
    build_execution_environment,
    parse_execution_environment_snapshot,
)
from mcp_toolhub.security.paths import (
    get_workspace_root,
    relative_workspace_path,
    resolve_workspace_path,
    validate_workspace_snapshot,
)
from mcp_toolhub.security.risk import RiskLevel

MAX_TIMEOUT_SECONDS = 60
MAX_OUTPUT_CHARS = 20_000


class ShellRunResult(ContractLifecycle):
    program: str
    args: list[str]
    cwd: str

    risk: RiskLevel
    risk_reason: str

    executed: bool
    returncode: int | None = None

    stdout: str = ""
    stderr: str = ""

    timed_out: bool = False

    request_id: str | None = None
    approval_status: ApprovalStatus | None = None
    message: str = ""


SHELL_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    open_world_hint=False,
)


def _truncate_output(value: str) -> str:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value

    remaining = len(value) - MAX_OUTPUT_CHARS

    return value[:MAX_OUTPUT_CHARS] + f"\n\n[ToolHub truncated {remaining} characters]"


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return value


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _execute_subprocess(
    program: str,
    args: list[str],
    working_directory: Path,
    timeout_seconds: int,
    risk: RiskLevel,
    risk_reason: str,
    *,
    tool: str,
    trace_id: str,
    action: str,
    execution_program: str,
    execution_environment: dict[str, str],
    policy_metadata: dict[str, object] | None = None,
    request_id: str | None = None,
    approval_status: ApprovalStatus | None = None,
    approval_handle: ApprovalHandle | None = None,
    message: str = "",
) -> ShellRunResult:
    """Execute a structured command with shell=False and return its result.

    Every outcome (success, non-zero exit, timeout, start failure) is
    recorded in the audit log.
    """
    relative_cwd = relative_workspace_path(working_directory)
    arguments = {"program": program, "args": args}
    audit_extra = (
        {"command_policy": policy_metadata} if policy_metadata is not None else None
    )
    started = time.monotonic()

    try:
        completed = subprocess.run(
            [execution_program, *args],
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
            check=False,
            env=execution_environment,
        )

    except subprocess.TimeoutExpired as exc:
        duration_ms = _elapsed_ms(started)
        audit.record_event(
            trace_id=trace_id,
            tool=tool,
            action="timeout",
            risk=risk,
            approval_status=approval_status,
            request_id=request_id,
            executed=True,
            success=False,
            duration_ms=duration_ms,
            arguments=arguments,
            cwd=relative_cwd,
            error=f"Command timed out after {timeout_seconds}s",
            error_type=type(exc).__name__,
            stdout_chars=len(_to_text(exc.stdout)),
            stderr_chars=len(_to_text(exc.stderr)),
            extra=audit_extra,
        )

        return ShellRunResult(
            outcome=ContractOutcome.TIMED_OUT,
            trace_id=trace_id,
            approval=approval_handle,
            error=make_contract_error(
                "COMMAND_TIMED_OUT",
                f"Command timed out after {timeout_seconds}s.",
            ),
            program=program,
            args=args,
            cwd=relative_cwd,
            risk=risk,
            risk_reason=risk_reason,
            executed=True,
            stdout=_truncate_output(_to_text(exc.stdout)),
            stderr=_truncate_output(_to_text(exc.stderr)),
            timed_out=True,
            request_id=request_id,
            approval_status=approval_status,
            message=message,
        )

    except OSError as exc:
        duration_ms = _elapsed_ms(started)
        audit.record_event(
            trace_id=trace_id,
            tool=tool,
            action="failure",
            risk=risk,
            approval_status=approval_status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=duration_ms,
            arguments=arguments,
            cwd=relative_cwd,
            error=str(exc),
            error_type=type(exc).__name__,
            extra=audit_extra,
        )

        return ShellRunResult(
            outcome=ContractOutcome.FAILED,
            trace_id=trace_id,
            approval=approval_handle,
            error=make_contract_error(
                "COMMAND_START_FAILED",
                "Approved command could not be started.",
            ),
            program=program,
            args=args,
            cwd=relative_cwd,
            risk=risk,
            risk_reason=risk_reason,
            executed=False,
            request_id=request_id,
            approval_status=approval_status,
            message=message or "Approved command could not be started.",
        )

    duration_ms = _elapsed_ms(started)
    success = completed.returncode == 0

    audit.record_event(
        trace_id=trace_id,
        tool=tool,
        action=action,
        risk=risk,
        approval_status=approval_status,
        request_id=request_id,
        executed=True,
        success=success,
        duration_ms=duration_ms,
        returncode=completed.returncode,
        arguments=arguments,
        cwd=relative_cwd,
        stdout_chars=len(completed.stdout),
        stderr_chars=len(completed.stderr),
        extra=audit_extra,
    )

    return ShellRunResult(
        outcome=(
            ContractOutcome.SUCCEEDED if success else ContractOutcome.COMMAND_FAILED
        ),
        trace_id=trace_id,
        approval=approval_handle,
        error=(
            None
            if success
            else make_contract_error(
                "COMMAND_NONZERO_EXIT",
                f"Command exited with return code {completed.returncode}.",
            )
        ),
        program=program,
        args=args,
        cwd=relative_cwd,
        risk=risk,
        risk_reason=risk_reason,
        executed=True,
        returncode=completed.returncode,
        stdout=_truncate_output(completed.stdout),
        stderr=_truncate_output(completed.stderr),
        request_id=request_id,
        approval_status=approval_status,
        message=message,
    )


def _execute_intrinsic_low(
    program: str,
    args: list[str],
    working_directory: Path,
    decision: CommandPolicyDecision,
    *,
    trace_id: str,
) -> ShellRunResult:
    """Return a LOW intrinsic result without starting a subprocess."""
    if decision.level != RiskLevel.LOW or decision.intrinsic_stdout is None:
        raise RuntimeError("Invalid intrinsic LOW command-policy decision")

    started = time.monotonic()
    relative_cwd = relative_workspace_path(working_directory)
    policy_metadata = decision.audit_metadata()
    stdout = decision.intrinsic_stdout

    audit.record_event(
        trace_id=trace_id,
        tool="shell.run",
        action="execute",
        risk=decision.level,
        executed=True,
        success=True,
        duration_ms=_elapsed_ms(started),
        returncode=0,
        arguments={"program": program, "args": args},
        cwd=relative_cwd,
        stdout_chars=len(stdout),
        stderr_chars=0,
        extra={"command_policy": policy_metadata},
    )

    return ShellRunResult(
        outcome=ContractOutcome.SUCCEEDED,
        trace_id=trace_id,
        program=program,
        args=args,
        cwd=relative_cwd,
        risk=decision.level,
        risk_reason=decision.reason,
        executed=True,
        returncode=0,
        stdout=stdout,
    )


def _resolve_working_directory(cwd: str) -> Path:
    working_directory = resolve_workspace_path(cwd)

    if not working_directory.exists():
        raise FileNotFoundError(f"Working directory not found: {cwd}")

    if not working_directory.is_dir():
        raise ValueError(f"Working directory is not a directory: {cwd}")

    return working_directory


def run_shell(
    program: str,
    args: list[str] | None = None,
    cwd: str = ".",
    timeout_seconds: int = 20,
) -> ShellRunResult:
    """Run a structured subprocess inside the ToolHub workspace.

    LOW-risk commands execute automatically. MEDIUM/HIGH commands create a
    PENDING approval request and do not execute.
    """

    trace_id = audit.new_trace_id()
    started = time.monotonic()
    command_args = list(args or [])

    try:
        working_directory = _resolve_working_directory(cwd)
    except (FileNotFoundError, ValueError) as exc:
        audit.record_event(
            trace_id=trace_id,
            tool="shell.run",
            action="failure",
            risk=RiskLevel.HIGH,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"program": program, "args": command_args},
            cwd=cwd,
            error=str(exc),
            error_type=type(exc).__name__,
            extra={
                "command_policy": {
                    "decision": "refused",
                    "risk": RiskLevel.HIGH.value,
                    "reason": (
                        "Working directory validation failed before executable "
                        "identity resolution."
                    ),
                }
            },
        )
        return ShellRunResult(
            outcome=ContractOutcome.REFUSED,
            trace_id=trace_id,
            error=make_contract_error(
                "WORKING_DIRECTORY_INVALID",
                str(exc),
            ),
            program=program,
            args=command_args,
            cwd=cwd,
            risk=RiskLevel.HIGH,
            risk_reason=(
                "Working directory validation failed before executable "
                "identity resolution."
            ),
            executed=False,
            message=str(exc),
        )

    assessment = assess_shell_command(
        program,
        command_args,
        working_directory=working_directory,
        workspace_root=get_workspace_root(),
    )
    policy_metadata = assessment.audit_metadata()
    timeout_seconds = max(1, min(timeout_seconds, MAX_TIMEOUT_SECONDS))
    relative_cwd = relative_workspace_path(working_directory)

    if assessment.level == RiskLevel.LOW:
        return _execute_intrinsic_low(
            program,
            command_args,
            working_directory,
            assessment,
            trace_id=trace_id,
        )

    execution_environment = build_execution_environment()

    try:
        executable_snapshot = resolve_executable_snapshot(
            program,
            working_directory=working_directory,
        )
    except (TypeError, ValueError) as exc:
        audit.record_event(
            trace_id=trace_id,
            tool="shell.run",
            action="failure",
            risk=assessment.level,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"program": program, "args": command_args},
            cwd=relative_cwd,
            error=str(exc),
            error_type="ExecutableResolutionError",
            extra={"command_policy": policy_metadata},
        )
        return ShellRunResult(
            outcome=ContractOutcome.REFUSED,
            trace_id=trace_id,
            error=make_contract_error(
                "EXECUTABLE_RESOLUTION_FAILED",
                str(exc),
            ),
            program=program,
            args=command_args,
            cwd=relative_cwd,
            risk=assessment.level,
            risk_reason=assessment.reason,
            executed=False,
            message=str(exc),
        )

    executable_metadata = executable_snapshot.to_payload()
    policy_metadata["approval_executable"] = executable_snapshot.audit_metadata(
        requested_program=program,
        workspace_root=get_workspace_root(),
    )
    policy_metadata["execution_environment"] = execution_environment.audit_metadata()
    request = approval.create_request(
        program=program,
        args=command_args,
        cwd=relative_cwd,
        timeout_seconds=timeout_seconds,
        risk=assessment.level,
        risk_reason=assessment.reason,
        payload={
            "workspace_root": str(get_workspace_root()),
            "command_policy": policy_metadata,
            "executable_snapshot": executable_metadata,
            "execution_environment": execution_environment.to_payload(),
        },
        trace_id=trace_id,
    )

    audit.record_event(
        trace_id=trace_id,
        tool="shell.run",
        action="approval_request",
        risk=assessment.level,
        approval_status=request.status,
        request_id=request.request_id,
        executed=False,
        success=True,
        duration_ms=_elapsed_ms(started),
        arguments={"program": program, "args": command_args},
        cwd=relative_cwd,
        extra={"command_policy": policy_metadata},
    )

    return ShellRunResult(
        outcome=ContractOutcome.APPROVAL_REQUIRED,
        trace_id=trace_id,
        approval=request.public_handle(),
        program=program,
        args=command_args,
        cwd=relative_cwd,
        risk=assessment.level,
        risk_reason=assessment.reason,
        executed=False,
        request_id=request.request_id,
        approval_status=request.status,
        message=(
            f"Approval required ({request.status.value}). "
            f"A trusted administrator must approve request "
            f"{request.request_id} before it can be run."
        ),
    )


def _rejected_result(
    request_id: str,
    *,
    trace_id: str,
    program: str = "",
    args: list[str] | None = None,
    cwd: str = ".",
    risk: RiskLevel = RiskLevel.HIGH,
    risk_reason: str = "",
    status: ApprovalStatus | None,
    message: str,
    approval_handle: ApprovalHandle | None = None,
    outcome: ContractOutcome | None = None,
    error_code: str | None = None,
) -> ShellRunResult:
    if status is None:
        resolved_outcome = outcome or ContractOutcome.REFUSED
        resolved_code = error_code or "REQUEST_NOT_FOUND"
        retryable = False
    else:
        resolved_outcome = outcome or outcome_for_approval_status(status)
        resolved_code = error_code or f"APPROVAL_{status.value}"
        retryable = status == ApprovalStatus.PENDING
    return ShellRunResult(
        outcome=resolved_outcome,
        trace_id=trace_id,
        approval=approval_handle,
        error=make_contract_error(resolved_code, message, retryable=retryable),
        program=program,
        args=list(args or []),
        cwd=cwd,
        risk=risk,
        risk_reason=risk_reason,
        executed=False,
        request_id=request_id,
        approval_status=status,
        message=message,
    )


def run_approved_shell(request_id: str) -> ShellRunResult:
    """Execute a previously-APPROVED command exactly as stored.

    This is the only execution path for MEDIUM/HIGH commands. It accepts no
    replacement program/args/cwd: it always replays the snapshot captured at
    request time, and the approval is consumed atomically so it cannot be
    replayed. Every refusal (unknown/PENDING/REJECTED/EXPIRED/CONSUMED) and
    execution outcome is audited.
    """

    trace_id = audit.new_trace_id()
    started = time.monotonic()
    policy_metadata: dict[str, object] | None = None

    def audit_rejection(
        *,
        status,
        error,
        error_type="ApprovalStateError",
        program="",
        args=None,
        cwd=".",
        risk=None,
    ):
        audit.record_event(
            trace_id=trace_id,
            tool="shell.run_approved",
            action="approval_rejected",
            risk=risk,
            approval_status=status,
            request_id=request_id,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"program": program, "args": list(args or [])},
            cwd=cwd,
            error=error,
            error_type=error_type,
            extra=(
                {"command_policy": policy_metadata}
                if policy_metadata is not None
                else None
            ),
        )

    request = approval.get_request(request_id)

    if request is None:
        audit_rejection(
            status=None,
            error=f"Unknown approval request: {request_id}",
            error_type="KeyError",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            status=None,
            risk_reason="Unknown approval request.",
            message=f"Unknown approval request: {request_id}",
        )

    trace_id = request.trace_id

    if request.status != ApprovalStatus.APPROVED:
        audit_rejection(
            status=request.status,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            error=f"Request is {request.status.value}; cannot execute.",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            risk_reason=request.risk_reason,
            status=request.status,
            message=f"Request is {request.status.value}; cannot execute.",
            approval_handle=request.public_handle(),
        )

    if request.kind != "shell":
        message = f"Approval request kind is {request.kind!r}; expected 'shell'."
        audit_rejection(
            status=request.status,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            error=message,
            error_type="ApprovalKindMismatch",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            risk_reason=request.risk_reason,
            status=request.status,
            message=message,
            approval_handle=request.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="APPROVAL_KIND_MISMATCH",
        )

    # Atomically APPROVED -> CONSUMED. Single-use: a second call fails here.
    consumed = approval.consume_request(request_id)

    if consumed is None:
        current = approval.get_request(request_id)
        status = current.status if current is not None else ApprovalStatus.EXPIRED
        audit_rejection(
            status=status,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            error=f"Approval could not be consumed (status {status.value}).",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            risk_reason=request.risk_reason,
            status=status,
            message=f"Approval could not be consumed (status {status.value}).",
            approval_handle=(current.public_handle() if current is not None else None),
        )

    stored_policy = consumed.payload.get("command_policy")
    if isinstance(stored_policy, dict):
        policy_metadata = stored_policy

    try:
        validate_workspace_snapshot(consumed.payload, get_workspace_root())
    except (TypeError, ValueError) as exc:
        message = f"Approval workspace identity is invalid: {exc}"
        audit_rejection(
            status=consumed.status,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            error=message,
            error_type="WorkspaceBoundaryViolation",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message=message,
            approval_handle=consumed.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="WORKSPACE_IDENTITY_INVALID",
        )

    try:
        execution_environment = parse_execution_environment_snapshot(
            consumed.payload.get("execution_environment")
        )
    except (TypeError, ValueError) as exc:
        message = (
            f"Approval execution environment is invalid: {exc} "
            "A new shell approval request is required."
        )
        audit_rejection(
            status=consumed.status,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            error=message,
            error_type="ExecutionEnvironmentMismatch",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message=message,
            approval_handle=consumed.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="EXECUTION_ENVIRONMENT_INVALID",
        )

    # Re-validate the stored cwd against the workspace (defense in depth).
    try:
        working_directory = resolve_workspace_path(consumed.cwd)
    except (OSError, RuntimeError, ValueError) as exc:
        audit_rejection(
            status=consumed.status,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            error="Stored cwd escapes the workspace; refused.",
            error_type=type(exc).__name__,
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message="Stored cwd escapes the workspace; refused.",
            approval_handle=consumed.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="WORKSPACE_BOUNDARY_VIOLATION",
        )

    if not working_directory.is_dir():
        audit_rejection(
            status=consumed.status,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            error="Stored cwd is not a directory; refused.",
            error_type="NotADirectoryError",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message="Stored cwd is not a directory; refused.",
            approval_handle=consumed.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="WORKING_DIRECTORY_INVALID",
        )

    timeout_seconds = max(1, min(consumed.timeout_seconds, MAX_TIMEOUT_SECONDS))

    try:
        execution_program = validate_executable_snapshot(
            consumed.payload.get("executable_snapshot")
        )
    except (TypeError, ValueError) as exc:
        message = f"Approved executable identity is no longer valid: {exc}"
        audit_rejection(
            status=consumed.status,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            error=message,
            error_type="ExecutableIdentityMismatch",
        )
        return _rejected_result(
            request_id,
            trace_id=trace_id,
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message=message,
            approval_handle=consumed.public_handle(),
            outcome=ContractOutcome.REFUSED,
            error_code="EXECUTABLE_IDENTITY_MISMATCH",
        )

    return _execute_subprocess(
        consumed.program,
        consumed.args,
        working_directory,
        timeout_seconds,
        consumed.risk,
        consumed.risk_reason,
        tool="shell.run_approved",
        trace_id=trace_id,
        action="execute_approved",
        execution_program=str(execution_program),
        execution_environment=execution_environment.environment(),
        policy_metadata=policy_metadata,
        request_id=request_id,
        approval_status=consumed.status,
        approval_handle=consumed.public_handle(),
    )


def register_shell_tools(mcp: MCPServer) -> None:
    """Register shell execution tools."""

    @mcp.tool(
        name="shell.run",
        title="Run workspace command",
        annotations=SHELL_ANNOTATIONS,
    )
    def run(
        program: str,
        args: list[str] | None = None,
        cwd: str = ".",
        timeout_seconds: int = 20,
    ) -> ShellRunResult:
        """
        Run a structured subprocess inside the ToolHub workspace.

        Only LOW-risk commands execute automatically. MEDIUM/HIGH commands
        create a PENDING approval request that a trusted administrator must
        approve out-of-band before it can be run via shell.run_approved.
        """
        return run_shell(program, args, cwd, timeout_seconds)

    @mcp.tool(
        name="shell.run_approved",
        title="Run an approved command",
        annotations=SHELL_ANNOTATIONS,
    )
    def run_approved(request_id: str) -> ShellRunResult:
        """
        Execute a previously-APPROVED command exactly as stored.

        Takes only a request_id; the program, args, and cwd are always the
        originals captured when the request was created. Approvals are
        single-use, so a request cannot be replayed.
        """
        return run_approved_shell(request_id)
