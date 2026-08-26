from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class RiskAssessment:
    level: RiskLevel
    reason: str


def assess_shell_command(program: str, args: list[str]) -> RiskAssessment:
    """Compatibility wrapper around the hardened command policy.

    Shell orchestration uses the full policy decision so LOW can be handled
    as an intrinsic ToolHub capability. Callers needing only a risk assessment
    keep this legacy API without retaining the old basename-only behavior.
    """
    from toolhub.security.command_policy import assess_shell_command as assess
    from toolhub.security.paths import get_workspace_root

    workspace = get_workspace_root()
    decision = assess(
        program,
        args,
        working_directory=workspace,
        workspace_root=workspace,
    )
    return RiskAssessment(decision.level, decision.reason)
