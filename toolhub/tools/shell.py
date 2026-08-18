import subprocess
import time
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from toolhub.observability import audit
from toolhub.security import approval
from toolhub.security.approval import ApprovalStatus
from toolhub.security.paths import (
    relative_workspace_path,
    resolve_workspace_path,
)
from toolhub.security.risk import (
    RiskLevel,
    assess_shell_command,
)


MAX_TIMEOUT_SECONDS = 60
MAX_OUTPUT_CHARS = 20_000


class ShellRunResult(BaseModel):
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

    return (
        value[:MAX_OUTPUT_CHARS]
        + f"\n\n[ToolHub truncated {remaining} characters]"
    )


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
    request_id: str | None = None,
    approval_status: ApprovalStatus | None = None,
    message: str = "",
) -> ShellRunResult:
    """Execute a structured command with shell=False and return its result.

    Every outcome (success, non-zero exit, timeout, start failure) is
    recorded in the audit log.
    """
    relative_cwd = relative_workspace_path(working_directory)
    arguments = {"program": program, "args": args}
    started = time.monotonic()

    try:
        completed = subprocess.run(
            [program, *args],
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
            check=False,
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
        )

        return ShellRunResult(
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
        )

        if isinstance(exc, FileNotFoundError):
            raise ValueError(f"Executable not found: {program}") from exc

        raise ValueError(f"Failed to start {program}: {exc}") from exc

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
    )

    return ShellRunResult(
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

    assessment = assess_shell_command(program, command_args)

    try:
        working_directory = _resolve_working_directory(cwd)
    except (FileNotFoundError, ValueError) as exc:
        audit.record_event(
            trace_id=trace_id,
            tool="shell.run",
            action="failure",
            risk=assessment.level,
            executed=False,
            success=False,
            duration_ms=_elapsed_ms(started),
            arguments={"program": program, "args": command_args},
            cwd=cwd,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        raise

    timeout_seconds = max(1, min(timeout_seconds, MAX_TIMEOUT_SECONDS))
    relative_cwd = relative_workspace_path(working_directory)

    if assessment.level == RiskLevel.LOW:
        return _execute_subprocess(
            program,
            command_args,
            working_directory,
            timeout_seconds,
            assessment.level,
            assessment.reason,
            tool="shell.run",
            trace_id=trace_id,
            action="execute",
        )

    request = approval.create_request(
        program=program,
        args=command_args,
        cwd=relative_cwd,
        timeout_seconds=timeout_seconds,
        risk=assessment.level,
        risk_reason=assessment.reason,
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
    )

    return ShellRunResult(
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
    program: str = "",
    args: list[str] | None = None,
    cwd: str = ".",
    risk: RiskLevel = RiskLevel.HIGH,
    risk_reason: str = "",
    status: ApprovalStatus | None,
    message: str,
) -> ShellRunResult:
    return ShellRunResult(
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

    def audit_rejection(*, status, error, error_type="ApprovalStateError", program="", args=None, cwd=".", risk=None):
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
            status=None,
            risk_reason="Unknown approval request.",
            message=f"Unknown approval request: {request_id}",
        )

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
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            risk_reason=request.risk_reason,
            status=request.status,
            message=f"Request is {request.status.value}; cannot execute.",
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
            program=request.program,
            args=request.args,
            cwd=request.cwd,
            risk=request.risk,
            risk_reason=request.risk_reason,
            status=status,
            message=f"Approval could not be consumed (status {status.value}).",
        )

    # Re-validate the stored cwd against the workspace (defense in depth).
    try:
        working_directory = resolve_workspace_path(consumed.cwd)
    except ValueError as exc:
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
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message="Stored cwd escapes the workspace; refused.",
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
            program=consumed.program,
            args=consumed.args,
            cwd=consumed.cwd,
            risk=consumed.risk,
            risk_reason=consumed.risk_reason,
            status=consumed.status,
            message="Stored cwd is not a directory; refused.",
        )

    timeout_seconds = max(1, min(consumed.timeout_seconds, MAX_TIMEOUT_SECONDS))

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
        request_id=request_id,
        approval_status=consumed.status,
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
