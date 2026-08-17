import subprocess
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

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


def _execute_subprocess(
    program: str,
    args: list[str],
    working_directory: Path,
    timeout_seconds: int,
    risk: RiskLevel,
    risk_reason: str,
    *,
    request_id: str | None = None,
    approval_status: ApprovalStatus | None = None,
    message: str = "",
) -> ShellRunResult:
    """Execute a structured command with shell=False and return its result."""
    relative_cwd = relative_workspace_path(working_directory)

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

    except FileNotFoundError as exc:
        raise ValueError(f"Executable not found: {program}") from exc

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

    command_args = list(args or [])

    assessment = assess_shell_command(program, command_args)

    working_directory = _resolve_working_directory(cwd)

    timeout_seconds = max(1, min(timeout_seconds, MAX_TIMEOUT_SECONDS))

    if assessment.level == RiskLevel.LOW:
        return _execute_subprocess(
            program,
            command_args,
            working_directory,
            timeout_seconds,
            assessment.level,
            assessment.reason,
        )

    request = approval.create_request(
        program=program,
        args=command_args,
        cwd=relative_workspace_path(working_directory),
        timeout_seconds=timeout_seconds,
        risk=assessment.level,
        risk_reason=assessment.reason,
    )

    return ShellRunResult(
        program=program,
        args=command_args,
        cwd=relative_workspace_path(working_directory),
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
    replayed.
    """

    request = approval.get_request(request_id)

    if request is None:
        return _rejected_result(
            request_id,
            status=None,
            risk_reason="Unknown approval request.",
            message=f"Unknown approval request: {request_id}",
        )

    if request.status != ApprovalStatus.APPROVED:
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
    except ValueError:
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
