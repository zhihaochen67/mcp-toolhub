"""Trusted ToolHub roots and workspace path containment helpers.

The agent workspace is selected once per process from
``TOOLHUB_WORKSPACE_ROOT``. ToolHub's project and state roots are derived
from the installed source location and never follow the workspace setting.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_ROOT = (PROJECT_ROOT / ".toolhub").resolve()
DEFAULT_WORKSPACE_ROOT = (PROJECT_ROOT / "workspace").resolve()

MAX_FILE_SIZE = 256 * 1024  # 256 KB


class WorkspaceConfigurationError(ValueError):
    """The trusted process-level workspace configuration is invalid."""


@dataclass(frozen=True)
class WorkspaceConfiguration:
    """Canonical roots shared by every tool for the life of the process."""

    project_root: Path
    state_root: Path
    workspace_root: Path
    configured_from_env: bool


_configuration: WorkspaceConfiguration | None = None
_configuration_lock = threading.Lock()


def _load_workspace_configuration() -> WorkspaceConfiguration:
    value = os.environ.get("TOOLHUB_WORKSPACE_ROOT")

    if value is None:
        candidate = DEFAULT_WORKSPACE_ROOT
        configured_from_env = False
    else:
        if not value.strip():
            raise WorkspaceConfigurationError(
                "Invalid TOOLHUB_WORKSPACE_ROOT: value is empty"
            )
        candidate = Path(value).expanduser()
        configured_from_env = True

    try:
        workspace_root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: path does not exist or cannot "
            f"be resolved: {candidate}"
        ) from exc

    if not workspace_root.is_dir():
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: path is not a directory: "
            f"{workspace_root}"
        )

    # The default approval/audit state must never become agent-addressable.
    # Reject a workspace equal to, or above, the fixed ToolHub state root.
    try:
        STATE_ROOT.relative_to(workspace_root)
    except ValueError:
        pass
    else:
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: workspace contains trusted "
            f"ToolHub state root: {STATE_ROOT}"
        )

    return WorkspaceConfiguration(
        project_root=PROJECT_ROOT,
        state_root=STATE_ROOT,
        workspace_root=workspace_root,
        configured_from_env=configured_from_env,
    )


def initialize_workspace_configuration() -> WorkspaceConfiguration:
    """Initialize and return the immutable process-level configuration.

    The MCP server calls this before registering tools. Direct library users
    initialize lazily on first use, which avoids capturing environment state
    merely by importing a tool module.
    """

    global _configuration

    if _configuration is None:
        with _configuration_lock:
            if _configuration is None:
                _configuration = _load_workspace_configuration()

    return _configuration


def get_workspace_root() -> Path:
    """Return the one canonical workspace boundary shared by all tools."""

    return initialize_workspace_configuration().workspace_root


def _reset_workspace_configuration_for_tests() -> None:
    """Clear process configuration so a test can model a fresh server."""

    global _configuration
    with _configuration_lock:
        _configuration = None


def resolve_path_within(path: str, root: Path | None = None) -> Path:
    """Resolve a user path and guarantee that it stays inside ``root``.

    When no explicit internal/test root is supplied, use the immutable
    process-level ToolHub workspace.
    """

    effective_root = (root or get_workspace_root()).resolve()
    target = (effective_root / path).resolve()

    try:
        target.relative_to(effective_root)
    except ValueError as exc:
        raise ValueError(
            f"Access denied: path escapes workspace: {path}"
        ) from exc

    return target


def resolve_workspace_path(path: str) -> Path:
    """Resolve a user path inside the configured process workspace."""

    return resolve_path_within(path, get_workspace_root())


def relative_workspace_path(path: Path) -> str:
    """Return a stable configured-workspace-relative path for MCP results."""

    relative = path.relative_to(get_workspace_root())

    if str(relative) == ".":
        return "."

    return relative.as_posix()
