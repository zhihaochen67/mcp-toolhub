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


def _default_state_environment(workspace: Path, state_base: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.pop("TOOLHUB_STATE_ROOT", None)
    environment["TOOLHUB_WORKSPACE_ROOT"] = str(workspace.resolve())
    if os.name == "nt":
        environment["LOCALAPPDATA"] = str(state_base.resolve())
        environment["APPDATA"] = str(state_base.resolve())
    else:
        environment["XDG_STATE_HOME"] = str(state_base.resolve())
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


async def _admin_command(
    admin: str,
    arguments: list[str],
    *,
    launch_directory: Path,
    environment: dict[str, str],
    confirmation: bool = False,
) -> tuple[int, str, str]:
    result = await anyio.run_process(
        [admin, *arguments],
        input=b"APPROVE\n" if confirmation else None,
        cwd=str(launch_directory),
        env=environment,
        check=False,
    )
    return (
        result.returncode,
        result.stdout.decode(errors="replace"),
        result.stderr.decode(errors="replace"),
    )


async def _exercise_two_workspace_isolation(
    server: str,
    admin: str,
    root: Path,
) -> None:
    workspace_a = root / "workspace-a"
    workspace_b = root / "workspace-b"
    state_base = root / "user-state-base"
    launch_a = root / "launch-a"
    launch_b = root / "launch-b"
    for directory in (workspace_a, workspace_b, state_base, launch_a, launch_b):
        directory.mkdir()

    environment_a = _default_state_environment(workspace_a, state_base)
    environment_b = _default_state_environment(workspace_b, state_base)
    parameters_a = StdioServerParameters(
        command=server,
        args=["serve"],
        cwd=launch_a,
        env=environment_a,
    )
    parameters_b = StdioServerParameters(
        command=server,
        args=["serve"],
        cwd=launch_b,
        env=environment_b,
    )

    async def request(session: ClientSession) -> str:
        result = _json_result(
            await session.call_tool(
                "shell.run",
                {"program": "git", "args": ["--version"]},
            )
        )
        assert result["executed"] is False
        return result["request_id"]

    async def approved(session: ClientSession, request_id: str) -> dict:
        return _json_result(
            await session.call_tool(
                "shell.run_approved",
                {"request_id": request_id},
            )
        )

    with anyio.fail_after(45):
        async with (
            stdio_client(parameters_a) as streams_a,
            ClientSession(*streams_a) as session_a,
            stdio_client(parameters_b) as streams_b,
            ClientSession(*streams_b) as session_b,
        ):
            await session_a.initialize()
            await session_b.initialize()

            request_a = await request(session_a)

            code, stdout, stderr = await _admin_command(
                admin,
                ["list"],
                launch_directory=launch_b,
                environment=environment_b,
            )
            assert code == 0, stderr
            assert request_a not in stdout

            audit_b = _json_result(
                await session_b.call_tool(
                    "toolhub.audit_recent",
                    {"limit": 100},
                )
            )
            assert request_a not in json.dumps(audit_b, sort_keys=True)

            code, stdout, stderr = await _admin_command(
                admin,
                ["approve", request_a],
                launch_directory=launch_a,
                environment=environment_a,
                confirmation=True,
            )
            assert code == 0, stderr
            assert json.dumps(str(workspace_a.resolve()), ensure_ascii=True) in stdout

            wrong_workspace = await approved(session_b, request_a)
            assert wrong_workspace["executed"] is False
            assert "Unknown approval request" in wrong_workspace["message"]

            code, stdout, stderr = await _admin_command(
                admin,
                ["list"],
                launch_directory=launch_a,
                environment=environment_a,
            )
            assert code == 0, stderr
            assert request_a in stdout
            assert "status:       APPROVED" in stdout

            own_a = await approved(session_a, request_a)
            assert own_a["executed"] is True
            replay_a = await approved(session_a, request_a)
            assert replay_a["executed"] is False

            request_b = await request(session_b)
            code, stdout, stderr = await _admin_command(
                admin,
                ["list"],
                launch_directory=launch_a,
                environment=environment_a,
            )
            assert code == 0, stderr
            assert request_b not in stdout

            code, stdout, stderr = await _admin_command(
                admin,
                ["approve", request_b],
                launch_directory=launch_b,
                environment=environment_b,
                confirmation=True,
            )
            assert code == 0, stderr
            assert json.dumps(str(workspace_b.resolve()), ensure_ascii=True) in stdout

            wrong_workspace = await approved(session_a, request_b)
            assert wrong_workspace["executed"] is False
            own_b = await approved(session_b, request_b)
            assert own_b["executed"] is True


def test_default_state_isolated_between_two_stdio_workspaces(external_runtime_dir):
    anyio.run(
        _exercise_two_workspace_isolation,
        _console_script("mcp-toolhub", "TOOLHUB_TEST_SERVER"),
        _console_script("mcp-toolhub-admin", "TOOLHUB_TEST_ADMIN"),
        external_runtime_dir,
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
