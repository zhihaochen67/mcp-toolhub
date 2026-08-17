from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

WORKSPACE_ROOT = (PROJECT_ROOT / "workspace").resolve()

MAX_FILE_SIZE = 256 * 1024  # 256 KB


def resolve_workspace_path(path: str) -> Path:
    """Resolve a user path and guarantee that it stays inside the workspace."""

    target = (WORKSPACE_ROOT / path).resolve()

    try:
        target.relative_to(WORKSPACE_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"Access denied: path escapes workspace: {path}"
        ) from exc

    return target


def relative_workspace_path(path: Path) -> str:
    """Return a stable workspace-relative path for MCP results."""

    relative = path.relative_to(WORKSPACE_ROOT)

    if str(relative) == ".":
        return "."

    return relative.as_posix()