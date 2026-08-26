"""Transport-level integration coverage for the installed ToolHub commands."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import anyio
import pytest
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
    "toolhub.ping",
}


def _console_script(name: str, override: str) -> str:
    configured = os.environ.get(override)
    if configured:
        return configured

    located = shutil.which(name)
    if located:
        return located

    scripts_dir = Path(sys.executable).parent
    candidate = scripts_dir / (f"{name}.exe" if os.name == "nt" else name)
    if candidate.is_file():
        return str(candidate)

    pytest.fail(f"Installed console script is unavailable: {name}")


@pytest.fixture
def external_runtime_dir():
    root = (
        Path(tempfile.gettempdir()).resolve()
        / f"mcp-toolhub-stdio-{secrets.token_hex(8)}"
    )
    repository = Path(__file__).resolve().parents[1]
    assert not root.is_relative_to(repository)
    root.mkdir()
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _runtime_layout(root: Path) -> tuple[Path, Path, Path]:
    workspace = root / "workspace"
    state_root = root / "state"
    launch_directory = root / "launch"
    workspace.mkdir(exist_ok=True)
    state_root.mkdir(exist_ok=True)
    launch_directory.mkdir(exist_ok=True)
    return workspace, state_root, launch_directory


def _runtime_environment(workspace: Path, state_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["TOOLHUB_WORKSPACE_ROOT"] = str(workspace.resolve())
    environment["TOOLHUB_STATE_ROOT"] = str(state_root.resolve())
    return environment


def _json_result(result) -> dict:
    assert result.is_error is False
    texts = [item.text for item in result.content if hasattr(item, "text")]
    assert texts
    return json.loads(texts[0])


async def _exercise_stdio(
    server: str,
    admin: str,
    workspace: Path,
    state_root: Path,
    launch_directory: Path,
) -> None:
    environment = _runtime_environment(workspace, state_root)
    marker = "workspace-marker-7d2f0a"
    (workspace / "marker.txt").write_text(marker, encoding="utf-8")
    parameters = StdioServerParameters(
        command=server,
        args=["serve"],
        cwd=launch_directory,
        env=environment,
    )

    with anyio.fail_after(20):
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams) as session:
                initialized = await session.initialize()
                assert initialized.server_info.name == "MCP ToolHub"
                assert initialized.server_info.version

                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                assert names == EXPECTED_TOOLS
                assert "toolhub.approve" not in names
                assert not any(name.startswith("admin.") for name in names)

                ping = _json_result(
                    await session.call_tool(
                        "toolhub.ping",
                        {"message": "stdio-integration"},
                    )
                )
                assert ping == {
                    "status": "ok",
                    "service": "mcp-toolhub",
                    "echo": "stdio-integration",
                }

                read = _json_result(
                    await session.call_tool(
                        "filesystem.read_file",
                        {"path": "marker.txt"},
                    )
                )
                assert read["path"] == "marker.txt"
                assert read["content"] == marker

                shell_request = _json_result(
                    await session.call_tool(
                        "shell.run",
                        {"program": "git", "args": ["--version"]},
                    )
                )
                assert shell_request["executed"] is False
                request_id = shell_request["request_id"]
                assert request_id.startswith("req_")

                admin_result = await anyio.run_process(
                    [admin, "list"],
                    cwd=str(launch_directory),
                    env=environment,
                    check=False,
                )
                admin_stderr = admin_result.stderr.decode(errors="replace")
                admin_stdout = admin_result.stdout.decode(errors="replace")
                assert admin_result.returncode == 0, admin_stderr
                assert request_id in admin_stdout


def test_stdio_initialize_tools_ping_workspace_and_admin_state(external_runtime_dir):
    workspace, state_root, launch_directory = _runtime_layout(external_runtime_dir)
    anyio.run(
        _exercise_stdio,
        _console_script("mcp-toolhub", "TOOLHUB_TEST_SERVER"),
        _console_script("mcp-toolhub-admin", "TOOLHUB_TEST_ADMIN"),
        workspace,
        state_root,
        launch_directory,
    )


@pytest.mark.parametrize(
    "case",
    ["missing", "empty", "nonexistent", "file", "state-inside-workspace"],
)
def test_expected_configuration_failures(case, external_runtime_dir):
    workspace, state_root, launch_directory = _runtime_layout(external_runtime_dir)
    environment = _runtime_environment(workspace, state_root)

    if case == "missing":
        environment.pop("TOOLHUB_WORKSPACE_ROOT")
    elif case == "empty":
        environment["TOOLHUB_WORKSPACE_ROOT"] = ""
    elif case == "nonexistent":
        environment["TOOLHUB_WORKSPACE_ROOT"] = str(external_runtime_dir / "missing")
    elif case == "file":
        file_path = external_runtime_dir / "not-a-directory"
        file_path.write_text("x", encoding="utf-8")
        environment["TOOLHUB_WORKSPACE_ROOT"] = str(file_path)
    else:
        nested_state = workspace / "state"
        nested_state.mkdir()
        environment["TOOLHUB_STATE_ROOT"] = str(nested_state)

    result = subprocess.run(
        [_console_script("mcp-toolhub", "TOOLHUB_TEST_SERVER"), "serve"],
        cwd=launch_directory,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr.strip()
    assert "Traceback" not in result.stderr
    assert len(result.stderr.splitlines()) <= 2
