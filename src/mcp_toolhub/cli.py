"""Production command-line entry point for MCP ToolHub."""

from __future__ import annotations

import argparse
import sys

from mcp_toolhub import __version__
from mcp_toolhub.app import create_server
from mcp_toolhub.security.paths import (
    RuntimeConfigurationError,
    initialize_runtime_configuration,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-toolhub",
        description="Secure MCP ToolHub server.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve", help="Run the MCP server over stdio only.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "serve":  # pragma: no cover - argparse constrains this
        raise AssertionError(f"Unsupported command: {args.command}")

    try:
        configuration = initialize_runtime_configuration()
        server = create_server(configuration)
    except RuntimeConfigurationError as exc:
        print(f"mcp-toolhub: {exc}", file=sys.stderr)
        return 2

    server.run("stdio")
    return 0
