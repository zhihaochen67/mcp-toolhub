from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class RiskAssessment:
    level: RiskLevel
    reason: str


SHELL_INTERPRETERS = {
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


DESTRUCTIVE_PROGRAMS = {
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


def _program_name(program: str) -> str:
    return Path(program).name.lower()


def _contains_escape_path(args: list[str]) -> bool:
    """Detect obvious attempts to access paths outside the workspace."""

    for arg in args:
        value = arg.strip()

        if not value or value.startswith("-"):
            continue

        if value == "..":
            return True

        if value.startswith("../") or value.startswith("..\\"):
            return True

        try:
            if Path(value).is_absolute():
                return True
        except OSError:
            pass

    return False


def assess_shell_command(
    program: str,
    args: list[str],
) -> RiskAssessment:
    """Classify a structured subprocess invocation."""

    executable = _program_name(program)
    lowered_args = [arg.lower() for arg in args]

    # Never allow a shell interpreter to bypass our structured runner.
    if executable in SHELL_INTERPRETERS:
        return RiskAssessment(
            RiskLevel.HIGH,
            "Shell interpreters can execute arbitrary command strings.",
        )

    if executable in DESTRUCTIVE_PROGRAMS:
        return RiskAssessment(
            RiskLevel.HIGH,
            f"Destructive executable detected: {executable}",
        )

    if _contains_escape_path(args):
        return RiskAssessment(
            RiskLevel.HIGH,
            "Arguments appear to reference a path outside the workspace.",
        )

    # Git commands that can modify remote/local state.
    if executable in {"git", "git.exe"}:
        if not lowered_args:
            return RiskAssessment(
                RiskLevel.LOW,
                "Git help/status information only.",
            )

        action = lowered_args[0]

        if action in {"push", "reset", "clean", "checkout", "switch", "restore"}:
            return RiskAssessment(
                RiskLevel.HIGH,
                f"Git operation may modify repository state: git {action}",
            )

        if action in {"status", "diff", "log", "show"}:
            return RiskAssessment(
                RiskLevel.LOW,
                f"Read-only Git operation: git {action}",
            )

        return RiskAssessment(
            RiskLevel.MEDIUM,
            f"Git operation requires review: git {action}",
        )

    # Starting Python itself is harmless when only querying version.
    if executable in {"python", "python.exe", "py", "py.exe"}:
        if lowered_args in [["--version"], ["-v"]]:
            return RiskAssessment(
                RiskLevel.LOW,
                "Interpreter version query.",
            )

        if "-c" in lowered_args:
            return RiskAssessment(
                RiskLevel.HIGH,
                "python -c can execute arbitrary inline code.",
            )

        if len(lowered_args) >= 2 and lowered_args[:2] == ["-m", "pytest"]:
            return RiskAssessment(
                RiskLevel.MEDIUM,
                "Running tests executes repository code.",
            )

        return RiskAssessment(
            RiskLevel.MEDIUM,
            "Running Python code executes local project code.",
        )

    if executable in {"pytest", "pytest.exe"}:
        if lowered_args == ["--version"]:
            return RiskAssessment(
                RiskLevel.LOW,
                "Pytest version query.",
            )

        return RiskAssessment(
            RiskLevel.MEDIUM,
            "Running tests executes repository code.",
        )

    # Deny-by-default.
    return RiskAssessment(
        RiskLevel.HIGH,
        f"Executable is not in the trusted policy: {executable}",
    )