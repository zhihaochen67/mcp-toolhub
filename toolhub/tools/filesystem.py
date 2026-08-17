from typing import Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from toolhub.security.paths import (
    MAX_FILE_SIZE,
    relative_workspace_path,
    resolve_workspace_path,
)


class ReadFileResult(BaseModel):
    path: str
    size: int
    content: str


class DirectoryEntry(BaseModel):
    name: str
    kind: Literal["file", "directory", "symlink", "other"]
    size: int | None = None


class ListDirectoryResult(BaseModel):
    path: str
    entries: list[DirectoryEntry]


READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)


def register_filesystem_tools(mcp: MCPServer) -> None:
    """Register filesystem tools on the MCP server."""

    @mcp.tool(
        name="filesystem.read_file",
        title="Read workspace file",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def read_file(path: str) -> ReadFileResult:
        """Read a UTF-8 text file inside the ToolHub workspace."""

        target = resolve_workspace_path(path)

        if not target.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not target.is_file():
            raise ValueError(f"Not a file: {path}")

        size = target.stat().st_size

        if size > MAX_FILE_SIZE:
            raise ValueError(
                f"File too large: {size} bytes "
                f"(maximum {MAX_FILE_SIZE} bytes)"
            )

        content = target.read_text(encoding="utf-8")

        return ReadFileResult(
            path=relative_workspace_path(target),
            size=size,
            content=content,
        )

    @mcp.tool(
        name="filesystem.list_directory",
        title="List workspace directory",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def list_directory(path: str = ".") -> ListDirectoryResult:
        """List files and directories inside the ToolHub workspace."""

        target = resolve_workspace_path(path)

        if not target.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        if not target.is_dir():
            raise ValueError(f"Not a directory: {path}")

        entries: list[DirectoryEntry] = []

        for item in sorted(target.iterdir(), key=lambda p: p.name.lower()):
            if item.is_symlink():
                kind = "symlink"
                size = None
            elif item.is_dir():
                kind = "directory"
                size = None
            elif item.is_file():
                kind = "file"
                size = item.stat().st_size
            else:
                kind = "other"
                size = None

            entries.append(
                DirectoryEntry(
                    name=item.name,
                    kind=kind,
                    size=size,
                )
            )

        return ListDirectoryResult(
            path=relative_workspace_path(target),
            entries=entries,
        )