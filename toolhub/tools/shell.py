import subprocess

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

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

        Only LOW-risk commands execute automatically.
        MEDIUM/HIGH commands require an approval system, which is added later.
        """

        command_args = args or []

        assessment = assess_shell_command(
            program,
            command_args,
        )

        working_directory = resolve_workspace_path(cwd)

        if not working_directory.exists():
            raise FileNotFoundError(
                f"Working directory not found: {cwd}"
            )

        if not working_directory.is_dir():
            raise ValueError(
                f"Working directory is not a directory: {cwd}"
            )

        timeout_seconds = max(
            1,
            min(timeout_seconds, MAX_TIMEOUT_SECONDS),
        )

        if assessment.level != RiskLevel.LOW:
            return ShellRunResult(
                program=program,
                args=command_args,
                cwd=relative_workspace_path(
                    working_directory
                ),
                risk=assessment.level,
                risk_reason=assessment.reason,
                executed=False,
            )

        try:
            completed = subprocess.run(
                [program, *command_args],
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
                args=command_args,
                cwd=relative_workspace_path(
                    working_directory
                ),
                risk=assessment.level,
                risk_reason=assessment.reason,
                executed=True,
                stdout=_truncate_output(
                    _to_text(exc.stdout)
                ),
                stderr=_truncate_output(
                    _to_text(exc.stderr)
                ),
                timed_out=True,
            )

        except FileNotFoundError as exc:
            raise ValueError(
                f"Executable not found: {program}"
            ) from exc

        return ShellRunResult(
            program=program,
            args=command_args,
            cwd=relative_workspace_path(
                working_directory
            ),
            risk=assessment.level,
            risk_reason=assessment.reason,
            executed=True,
            returncode=completed.returncode,
            stdout=_truncate_output(completed.stdout),
            stderr=_truncate_output(completed.stderr),
        )