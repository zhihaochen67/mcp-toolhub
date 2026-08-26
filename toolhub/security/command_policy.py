"""Small, deny-by-default policy for structured shell commands.

LOW is reserved for intrinsic ToolHub operations. A LOW command never
searches PATH and never starts a user-selected executable. The only current
capability reports the version of the Python runtime already hosting ToolHub.

No PATH directory is trusted merely because it is absolute or outside the
workspace. Commands whose executable provenance is not established by an
intrinsic binding require approval (MEDIUM or HIGH).
"""

from __future__ import annotations

import ntpath
import os
import platform
import posixpath
import sys
from dataclasses import dataclass
from pathlib import Path

from toolhub.security.paths import get_workspace_root
from toolhub.security.risk import RiskLevel

_WINDOWS = os.name == "nt"

SHELL_INTERPRETERS = frozenset(
    {
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "bash",
        "sh",
        "zsh",
    }
)

DESTRUCTIVE_PROGRAMS = frozenset(
    {
        "rm",
        "del",
        "erase",
        "rmdir",
        "rd",
        "format",
        "diskpart",
        "shutdown",
        "reboot",
    }
)

PYTHON_NAMES = frozenset(
    {"python", "python.exe", "python3", "python3.exe"}
)
PYTHON_LAUNCHER_NAMES = frozenset({"py", "py.exe"})
PYTEST_NAMES = frozenset({"pytest", "pytest.exe"})
GIT_NAMES = frozenset({"git", "git.exe"})
WINDOWS_SCRIPT_EXTENSIONS = frozenset({".bat", ".cmd"})

# These are policy aliases, not PATH lookups. In a LOW profile they mean the
# already-running ToolHub runtime. The Windows py launcher is intentionally
# absent because it performs another interpreter selection.
PYTHON_RUNTIME_ALIASES = frozenset(
    {"python", "python3"}
    | ({"python.exe", "python3.exe"} if _WINDOWS else set())
)


@dataclass(frozen=True)
class LowCommandProfile:
    """One exact intrinsic LOW capability."""

    name: str
    args: tuple[str, ...]
    argument_shape: str


LOW_COMMAND_PROFILES = (
    LowCommandProfile(
        name="python.version.long",
        args=("--version",),
        argument_shape="python --version",
    ),
    LowCommandProfile(
        name="python.version.short",
        args=("-V",),
        argument_shape="python -V",
    ),
)


@dataclass(frozen=True)
class ExecutableIdentity:
    """Executable provenance recorded with a policy decision."""

    lookup: str
    resolved_path: Path | None
    trusted: bool
    reason: str
    path_name: str | None = None

    def audit_metadata(self) -> dict[str, object]:
        metadata: dict[str, object] = {
            "lookup": self.lookup,
            "trusted": self.trusted,
            "reason": self.reason,
            "requested_name": self.path_name,
            "resolved_name": (
                self.resolved_path.name
                if self.resolved_path is not None
                else self.path_name
            ),
        }
        if self.lookup == "toolhub_runtime":
            metadata["scope"] = "toolhub_runtime"
        elif self.resolved_path is None:
            metadata["scope"] = "unresolved"
        else:
            try:
                workspace_path = self.resolved_path.relative_to(
                    get_workspace_root()
                )
            except ValueError:
                metadata["scope"] = "external"
            else:
                metadata["scope"] = "workspace"
                metadata["workspace_path"] = workspace_path.as_posix()
        return metadata


@dataclass(frozen=True)
class CommandPolicyDecision:
    """Complete classification and any intrinsic LOW result."""

    level: RiskLevel
    reason: str
    executable: ExecutableIdentity
    profile: str | None = None
    argument_shape: str | None = None
    intrinsic_stdout: str | None = None

    def audit_metadata(self) -> dict[str, object]:
        return {
            "decision": (
                "auto_execute" if self.level == RiskLevel.LOW else "approval_required"
            ),
            "risk": self.level.value,
            "reason": self.reason,
            "profile": self.profile,
            "argument_shape": self.argument_shape,
            "execution_kind": (
                "intrinsic" if self.intrinsic_stdout is not None else "subprocess"
            ),
            "executable": self.executable.audit_metadata(),
        }


def _program_name(program: str) -> str:
    """Return a platform-normalized basename for command-family checks."""
    name = ntpath.basename(program)
    return name.casefold() if _WINDOWS else name


def _is_explicit_path(program: str) -> bool:
    return (
        "/" in program
        or "\\" in program
        or ntpath.isabs(program)
        or posixpath.isabs(program)
    )


def _runtime_identity(
    runtime_executable: str | os.PathLike[str],
) -> ExecutableIdentity:
    """Identify the operator-selected runtime already hosting ToolHub."""
    candidate = Path(runtime_executable)
    if not candidate.is_absolute():
        return ExecutableIdentity(
            lookup="toolhub_runtime",
            resolved_path=None,
            trusted=False,
            reason="ToolHub's sys.executable is not an absolute path.",
        )

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return ExecutableIdentity(
            lookup="toolhub_runtime",
            resolved_path=None,
            trusted=False,
            reason="ToolHub's sys.executable could not be resolved.",
        )

    if not resolved.is_file():
        return ExecutableIdentity(
            lookup="toolhub_runtime",
            resolved_path=resolved,
            trusted=False,
            reason="ToolHub's sys.executable is not a regular file.",
        )

    return ExecutableIdentity(
        lookup="toolhub_runtime",
        resolved_path=resolved,
        trusted=True,
        reason=(
            "Bound to the operator-selected Python runtime already hosting "
            "ToolHub; PATH was not consulted."
        ),
        path_name=resolved.name,
    )


def _unverified_identity(
    program: str,
    working_directory: Path,
) -> ExecutableIdentity:
    """Describe a requested executable without granting it provenance."""
    resolved: Path | None = None
    lookup = "unresolved_name"

    if _is_explicit_path(program):
        lookup = "explicit_path"
        candidate = Path(program)
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            resolved = None

    return ExecutableIdentity(
        lookup=lookup,
        resolved_path=resolved,
        trusted=False,
        reason=(
            "Executable provenance is unverified; PATH entries and arbitrary "
            "explicit paths are never trusted for automatic execution."
        ),
        path_name=_program_name(program),
    )


def _is_bound_runtime_request(
    program: str,
    runtime: ExecutableIdentity,
) -> bool:
    """Whether the request is explicitly bound to the ToolHub runtime."""
    if not runtime.trusted or runtime.resolved_path is None:
        return False

    if not _is_explicit_path(program):
        return _program_name(program) in PYTHON_RUNTIME_ALIASES

    candidate = Path(program)
    if not candidate.is_absolute():
        return False

    try:
        return candidate.resolve(strict=True) == runtime.resolved_path
    except (OSError, RuntimeError):
        return False


def _contains_escape_path(args: list[str]) -> bool:
    """Detect obvious argument paths outside the workspace."""
    for arg in args:
        value = arg.strip()
        if not value or value.startswith("-"):
            continue
        if value == ".." or value.startswith(("../", "..\\")):
            return True
        if ntpath.isabs(value) or posixpath.isabs(value):
            return True
    return False


def assess_shell_command(
    program: str,
    args: list[str],
    *,
    working_directory: Path,
    workspace_root: Path | None = None,
    environment: object | None = None,
) -> CommandPolicyDecision:
    """Classify a command; only intrinsic runtime queries can be LOW.

    workspace_root and environment remain keyword-compatible with the earlier
    policy API. LOW classification deliberately does not inspect PATH or
    PATHEXT.
    """
    del environment
    (workspace_root or get_workspace_root()).resolve()

    runtime = _runtime_identity(sys.executable)
    requested_name = _program_name(program)

    if requested_name in SHELL_INTERPRETERS:
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            "Shell interpreters can execute arbitrary command strings.",
            _unverified_identity(program, working_directory),
        )

    if requested_name in DESTRUCTIVE_PROGRAMS:
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            f"Destructive executable detected: {requested_name}",
            _unverified_identity(program, working_directory),
        )

    if requested_name in PYTHON_LAUNCHER_NAMES:
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            "The py launcher selects another Python interpreter at execution time.",
            _unverified_identity(program, working_directory),
        )

    if ntpath.splitext(requested_name)[1].casefold() in WINDOWS_SCRIPT_EXTENSIONS:
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            "Windows batch scripts execute through a command interpreter.",
            _unverified_identity(program, working_directory),
        )

    if _is_bound_runtime_request(program, runtime):
        for profile in LOW_COMMAND_PROFILES:
            if tuple(args) == profile.args:
                return CommandPolicyDecision(
                    RiskLevel.LOW,
                    (
                        f"Exact intrinsic LOW profile {profile.name} is bound "
                        "to the running ToolHub Python runtime."
                    ),
                    runtime,
                    profile=profile.name,
                    argument_shape=profile.argument_shape,
                    intrinsic_stdout=f"Python {platform.python_version()}\n",
                )

    identity = _unverified_identity(program, working_directory)

    if _contains_escape_path(args):
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            "Arguments appear to reference a path outside the workspace.",
            identity,
        )

    if requested_name in GIT_NAMES:
        return CommandPolicyDecision(
            RiskLevel.HIGH,
            (
                "Generic Git is approval-gated because configuration, hooks, "
                "pagers, helpers, and subcommands can execute code or mutate state."
            ),
            identity,
        )

    if requested_name in PYTHON_NAMES:
        lowered_args = [arg.casefold() for arg in args]
        if "-c" in lowered_args:
            return CommandPolicyDecision(
                RiskLevel.HIGH,
                "python -c can execute arbitrary inline code.",
                identity,
            )
        return CommandPolicyDecision(
            RiskLevel.MEDIUM,
            (
                "Python is not bound to an exact intrinsic LOW profile; "
                "executable provenance or arguments require approval."
            ),
            identity,
        )

    if requested_name in PYTEST_NAMES:
        return CommandPolicyDecision(
            RiskLevel.MEDIUM,
            "Pytest may load plugins or execute repository code.",
            identity,
        )

    return CommandPolicyDecision(
        RiskLevel.HIGH,
        f"Executable has no automatic command policy: {requested_name}",
        identity,
    )
