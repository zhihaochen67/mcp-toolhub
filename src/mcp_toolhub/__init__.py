"""MCP ToolHub package metadata."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-toolhub")
except PackageNotFoundError:  # pragma: no cover - source without installation
    __version__ = "0+unknown"

__all__ = ["__version__"]
