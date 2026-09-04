"""Two-phase public MCP client for the ToolHub portfolio demo."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

EXPECTED_TOOLS = {
    "filesystem.apply_patch",
    "filesystem.apply_patch_approved",
    "filesystem.list_directory",
    "filesystem.read_file",
    "filesystem.write_file",
    "filesystem.write_file_approved",
    "git.diff",
    "git.status",
    "shell.run",
    "shell.run_approved",
    "toolhub.audit_recent",
    "toolhub.capabilities",
    "toolhub.ping",
    "toolhub.request_status",
}


def _structured(result) -> dict:
    if result.is_error or result.structured_content is None:
        raise RuntimeError(f"MCP tool call failed: {result}")
    return result.structured_content


def _show(label: str, value) -> None:
    print(f"\n{label}")
    print(json.dumps(value, indent=2, sort_keys=True))


def _runtime_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("TOOLHUB_WORKSPACE_ROOT", "TOOLHUB_STATE_ROOT"):
        value = environment.get(name)
        if not value:
            raise RuntimeError(f"{name} must be set for the demo")
        if not Path(value).is_absolute():
            raise RuntimeError(f"{name} must be an absolute path")
    return environment


async def _run(phase: str, request_id: str | None) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_toolhub", "serve"],
        cwd=Path.cwd(),
        env=_runtime_environment(),
    )

    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        initialized = await session.initialize()
        print(
            "initialize:",
            initialized.server_info.name,
            initialized.server_info.version,
        )

        if phase == "submit":
            listed = await session.list_tools()
            tool_names = {tool.name for tool in listed.tools}
            if tool_names != EXPECTED_TOOLS:
                raise RuntimeError(
                    "Unexpected tool inventory: "
                    f"{sorted(tool_names)} (expected {sorted(EXPECTED_TOOLS)})"
                )
            print(f"tools/list ({len(tool_names)}):")
            print("\n".join(f"  {name}" for name in sorted(tool_names)))

            capabilities = _structured(
                await session.call_tool("toolhub.capabilities", {})
            )
            _show(
                "toolhub.capabilities:",
                {
                    "contract_version": capabilities["contract_version"],
                    "package_version": capabilities["package_version"],
                    "transport": capabilities["transport"],
                    "approval_model": capabilities["approval_model"],
                },
            )

            seed = _structured(
                await session.call_tool(
                    "filesystem.read_file",
                    {"path": "seed.txt"},
                )
            )
            _show("filesystem.read_file:", seed)

            submitted = _structured(
                await session.call_tool(
                    "filesystem.write_file",
                    {
                        "path": "approved.txt",
                        "content": "Approved by a human.\n",
                    },
                )
            )
            if submitted["outcome"] != "APPROVAL_REQUIRED":
                raise RuntimeError(f"Unexpected submission result: {submitted}")
            _show("filesystem.write_file:", submitted)
            print("\nCopy these values:")
            print(f"REQUEST_ID={submitted['request_id']}")
            print(f"TRACE_ID={submitted['trace_id']}")
            return

        if request_id is None:
            raise RuntimeError("resume requires a request ID")

        status = _structured(
            await session.call_tool(
                "toolhub.request_status",
                {"request_id": request_id},
            )
        )
        _show("toolhub.request_status:", status)
        if status["outcome"] != "APPROVAL_APPROVED":
            raise RuntimeError("Request is not approved. Use mcp-toolhub-admin first.")

        trace_id = status["trace_id"]
        resumed = _structured(
            await session.call_tool(
                "filesystem.write_file_approved",
                {"request_id": request_id},
            )
        )
        _show("filesystem.write_file_approved:", resumed)
        if resumed["outcome"] != "SUCCEEDED":
            raise RuntimeError(f"Unexpected resume result: {resumed}")

        audit = _structured(
            await session.call_tool("toolhub.audit_recent", {"limit": 20})
        )
        correlated = [
            event for event in audit["events"] if event.get("trace_id") == trace_id
        ]
        _show("toolhub.audit_recent (matching trace_id):", correlated)

        replay = _structured(
            await session.call_tool(
                "filesystem.write_file_approved",
                {"request_id": request_id},
            )
        )
        _show("resume replay:", replay)
        if replay["outcome"] != "APPROVAL_CONSUMED":
            raise RuntimeError(f"Unexpected replay result: {replay}")

        written = _structured(
            await session.call_tool(
                "filesystem.read_file",
                {"path": "approved.txt"},
            )
        )
        _show("filesystem.read_file approved.txt:", written)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    subparsers.add_parser("submit", help="Inspect and submit a write request.")
    resume = subparsers.add_parser(
        "resume",
        help="Observe, execute, audit, and replay an approved request.",
    )
    resume.add_argument("request_id")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        anyio.run(_run, args.phase, getattr(args, "request_id", None))
    except (RuntimeError, OSError) as exc:
        print(f"demo error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
