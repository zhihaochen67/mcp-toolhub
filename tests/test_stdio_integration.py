"""Transport-level integration coverage for the installed ToolHub commands."""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
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
    "toolhub.capabilities",
    "toolhub.ping",
    "toolhub.request_status",
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
    assert result.structured_content is not None
    return result.structured_content


def _process_exists(pid: int) -> bool:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x00100000 | 0x00001000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x00000102
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _exercise_stdio(
    server: str,
    admin: str,
    workspace: Path,
    state_root: Path,
    launch_directory: Path,
) -> None:
    environment = _runtime_environment(workspace, state_root)
    secret_name = "TOOLHUB_TEST_SECRET_TOKEN"
    secret_value = "installed-wheel-parent-secret-b6d2"
    environment[secret_name] = secret_value
    marker = "workspace-marker-7d2f0a"
    (workspace / "marker.txt").write_text(marker, encoding="utf-8")
    parameters = StdioServerParameters(
        command=server,
        args=["serve"],
        cwd=launch_directory,
        env=environment,
    )

    with anyio.fail_after(60):
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

                capabilities = _json_result(
                    await session.call_tool("toolhub.capabilities", {})
                )
                assert capabilities["contract_version"] == "1.0"
                assert capabilities["transport"] == "stdio"

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

                write_request = _json_result(
                    await session.call_tool(
                        "filesystem.write_file",
                        {"path": "contract.txt", "content": "before\n"},
                    )
                )
                assert write_request["outcome"] == "APPROVAL_REQUIRED"
                write_handle = write_request["approval"]
                assert write_handle["request_id"] == write_request["request_id"]
                assert write_handle["resume_tool"] == "filesystem.write_file_approved"
                assert write_handle["expires_at"]
                write_trace = write_request["trace_id"]

                write_pending = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": write_handle["request_id"]},
                    )
                )
                assert write_pending["outcome"] == "APPROVAL_PENDING"
                assert write_pending["trace_id"] == write_trace

                code, _stdout, stderr = await _admin_command(
                    admin,
                    ["approve", write_handle["request_id"]],
                    launch_directory=launch_directory,
                    environment=environment,
                    confirmation=True,
                )
                assert code == 0, stderr
                write_approved = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": write_handle["request_id"]},
                    )
                )
                assert write_approved["outcome"] == "APPROVAL_APPROVED"
                assert write_approved["trace_id"] == write_trace

                write_done = _json_result(
                    await session.call_tool(
                        write_handle["resume_tool"],
                        {"request_id": write_handle["request_id"]},
                    )
                )
                assert write_done["outcome"] == "SUCCEEDED"
                assert write_done["trace_id"] == write_trace
                assert write_done["executed"] is True
                read_written = _json_result(
                    await session.call_tool(
                        "filesystem.read_file", {"path": "contract.txt"}
                    )
                )
                assert read_written["content"] == "before\n"

                write_consumed = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": write_handle["request_id"]},
                    )
                )
                assert write_consumed["outcome"] == "APPROVAL_CONSUMED"
                assert write_consumed["trace_id"] == write_trace
                write_replay = _json_result(
                    await session.call_tool(
                        write_handle["resume_tool"],
                        {"request_id": write_handle["request_id"]},
                    )
                )
                assert write_replay["outcome"] == "APPROVAL_CONSUMED"
                assert write_replay["error"]["code"] == "APPROVAL_CONSUMED"
                assert write_replay["trace_id"] == write_trace

                patch_request = _json_result(
                    await session.call_tool(
                        "filesystem.apply_patch",
                        {
                            "path": "contract.txt",
                            "patch": (
                                "--- contract.txt\n"
                                "+++ contract.txt\n"
                                "@@ -1,1 +1,1 @@\n"
                                "-before\n"
                                "+after\n"
                            ),
                        },
                    )
                )
                assert patch_request["outcome"] == "APPROVAL_REQUIRED"
                patch_handle = patch_request["approval"]
                patch_trace = patch_request["trace_id"]
                assert patch_handle["resume_tool"] == "filesystem.apply_patch_approved"
                patch_pending = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": patch_handle["request_id"]},
                    )
                )
                assert patch_pending["outcome"] == "APPROVAL_PENDING"
                assert patch_pending["trace_id"] == patch_trace
                code, _stdout, stderr = await _admin_command(
                    admin,
                    ["approve", patch_handle["request_id"]],
                    launch_directory=launch_directory,
                    environment=environment,
                    confirmation=True,
                )
                assert code == 0, stderr
                patch_approved = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": patch_handle["request_id"]},
                    )
                )
                assert patch_approved["outcome"] == "APPROVAL_APPROVED"
                assert patch_approved["trace_id"] == patch_trace
                patch_done = _json_result(
                    await session.call_tool(
                        patch_handle["resume_tool"],
                        {"request_id": patch_handle["request_id"]},
                    )
                )
                assert patch_done["outcome"] == "SUCCEEDED"
                assert patch_done["trace_id"] == patch_trace
                assert patch_done["changed"] is True
                assert (workspace / "contract.txt").read_text(encoding="utf-8") == (
                    "after\n"
                )
                patch_consumed = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": patch_handle["request_id"]},
                    )
                )
                assert patch_consumed["outcome"] == "APPROVAL_CONSUMED"
                assert patch_consumed["trace_id"] == patch_trace
                patch_replay = _json_result(
                    await session.call_tool(
                        patch_handle["resume_tool"],
                        {"request_id": patch_handle["request_id"]},
                    )
                )
                assert patch_replay["outcome"] == "APPROVAL_CONSUMED"
                assert patch_replay["error"]["code"] == "APPROVAL_CONSUMED"

                rejected_request = _json_result(
                    await session.call_tool(
                        "filesystem.write_file",
                        {"path": "rejected.txt", "content": "must-not-run"},
                    )
                )
                rejected_handle = rejected_request["approval"]
                code, _stdout, stderr = await _admin_command(
                    admin,
                    ["reject", rejected_handle["request_id"]],
                    launch_directory=launch_directory,
                    environment=environment,
                )
                assert code == 0, stderr
                rejected_status = _json_result(
                    await session.call_tool(
                        "toolhub.request_status",
                        {"request_id": rejected_handle["request_id"]},
                    )
                )
                assert rejected_status["outcome"] == "APPROVAL_REJECTED"
                rejected_resume = _json_result(
                    await session.call_tool(
                        rejected_handle["resume_tool"],
                        {"request_id": rejected_handle["request_id"]},
                    )
                )
                assert rejected_resume["outcome"] == "APPROVAL_REJECTED"
                assert rejected_resume["error"]["code"] == "APPROVAL_REJECTED"
                assert not (workspace / "rejected.txt").exists()

                runtime_python = Path(server).parent / (
                    "python.exe" if os.name == "nt" else "python"
                )
                assert runtime_python.is_file()
                shell_request = _json_result(
                    await session.call_tool(
                        "shell.run",
                        {
                            "program": str(runtime_python),
                            "args": [
                                "-c",
                                (
                                    "import os; print('toolhub-shell-ok'); "
                                    f"print(os.environ.get({secret_name!r}, 'ABSENT'))"
                                ),
                            ],
                        },
                    )
                )
                assert shell_request["outcome"] == "APPROVAL_REQUIRED"
                assert shell_request["executed"] is False
                assert secret_value not in json.dumps(shell_request)
                request_id = shell_request["request_id"]
                assert request_id.startswith("req_")
                shell_trace = shell_request["trace_id"]
                shell_handle = shell_request["approval"]
                assert shell_handle["resume_tool"] == "shell.run_approved"

                raw_store = (state_root / "approvals.json").read_text(encoding="utf-8")
                stored_request = json.loads(raw_store)["requests"][request_id]
                stored_environment = stored_request["payload"]["execution_environment"]
                assert stored_environment["policy_version"] == 1
                assert len(stored_environment["sha256"]) == 64
                assert secret_name not in stored_environment["variables"]
                assert secret_value not in raw_store

                code, admin_stdout, admin_stderr = await _admin_command(
                    admin,
                    ["list"],
                    launch_directory=launch_directory,
                    environment=environment,
                )
                assert code == 0, admin_stderr
                assert request_id in admin_stdout
                assert secret_value not in admin_stdout
                code, _stdout, admin_stderr = await _admin_command(
                    admin,
                    ["approve", request_id],
                    launch_directory=launch_directory,
                    environment=environment,
                    confirmation=True,
                )
                assert code == 0, admin_stderr
                shell_done = _json_result(
                    await session.call_tool(
                        shell_handle["resume_tool"], {"request_id": request_id}
                    )
                )
                assert shell_done["outcome"] == "SUCCEEDED"
                assert shell_done["trace_id"] == shell_trace
                assert shell_done["returncode"] == 0
                assert shell_done["stdout"] == "toolhub-shell-ok\nABSENT\n"
                assert secret_value not in json.dumps(shell_done)

                large_request = _json_result(
                    await session.call_tool(
                        "shell.run",
                        {
                            "program": str(runtime_python),
                            "args": [
                                "-c",
                                (
                                    "import sys\n"
                                    "chunk = b'L' * 65536\n"
                                    "for _ in range(64):\n"
                                    "    sys.stdout.buffer.write(chunk)\n"
                                    "    sys.stderr.buffer.write(chunk)\n"
                                    "    sys.stdout.buffer.flush()\n"
                                    "    sys.stderr.buffer.flush()\n"
                                ),
                            ],
                        },
                    )
                )
                assert large_request["outcome"] == "APPROVAL_REQUIRED"
                large_id = large_request["request_id"]
                large_handle = large_request["approval"]
                code, _stdout, admin_stderr = await _admin_command(
                    admin,
                    ["approve", large_id],
                    launch_directory=launch_directory,
                    environment=environment,
                    confirmation=True,
                )
                assert code == 0, admin_stderr
                large_done = _json_result(
                    await session.call_tool(
                        large_handle["resume_tool"],
                        {"request_id": large_id},
                    )
                )
                # Discarded output is a reporting fact, not a failure.
                assert large_done["outcome"] == "SUCCEEDED"
                assert large_done["returncode"] == 0
                assert large_done["stdout"].startswith("L" * 20_000)
                assert "\n\n[ToolHub discarded " in large_done["stdout"]
                assert large_done["stdout"].endswith(" output bytes]")
                assert len(large_done["stdout"]) <= 20_000 + 64
                assert large_done["stderr"].startswith("L" * 20_000)
                assert "\n\n[ToolHub discarded " in large_done["stderr"]
                assert len(large_done["stderr"]) <= 20_000 + 64

                child_pid_file = workspace / "timed-out-child.pid"
                child_code = "import time; time.sleep(60)"
                parent_code = (
                    "import subprocess,sys,time; from pathlib import Path; "
                    f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}],"
                    "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
                    "Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii'); "
                    "print('child-ready',flush=True); time.sleep(60)"
                )
                timeout_request = _json_result(
                    await session.call_tool(
                        "shell.run",
                        {
                            "program": str(runtime_python),
                            "args": ["-c", parent_code, str(child_pid_file)],
                            "timeout_seconds": 1,
                        },
                    )
                )
                assert timeout_request["outcome"] == "APPROVAL_REQUIRED"
                timeout_id = timeout_request["request_id"]
                code, _stdout, admin_stderr = await _admin_command(
                    admin,
                    ["approve", timeout_id],
                    launch_directory=launch_directory,
                    environment=environment,
                    confirmation=True,
                )
                assert code == 0, admin_stderr
                timeout_done = _json_result(
                    await session.call_tool(
                        "shell.run_approved",
                        {"request_id": timeout_id},
                    )
                )
                assert timeout_done["outcome"] == "TIMED_OUT"
                assert timeout_done["error"]["code"] == "COMMAND_TIMED_OUT"
                assert timeout_done["executed"] is True
                assert timeout_done["timed_out"] is True
                assert "child-ready" in timeout_done["stdout"]
                child_pid = int(child_pid_file.read_text(encoding="ascii"))
                deadline = time.monotonic() + 5
                while _process_exists(child_pid) and time.monotonic() < deadline:
                    await anyio.sleep(0.01)
                assert not _process_exists(child_pid)


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
            assert wrong_workspace["outcome"] == "REFUSED"
            assert wrong_workspace["error"]["code"] == "REQUEST_NOT_FOUND"

            other_status = _json_result(
                await session_b.call_tool(
                    "toolhub.request_status",
                    {"request_id": request_a},
                )
            )
            unknown_status = _json_result(
                await session_b.call_tool(
                    "toolhub.request_status",
                    {"request_id": "req_" + "0" * 32},
                )
            )
            for result in (other_status, unknown_status):
                assert result["outcome"] == "REFUSED"
                assert result["approval"] is None
                assert result["error"] == {
                    "code": "REQUEST_NOT_FOUND",
                    "message": "Approval request is unavailable.",
                    "retryable": False,
                }
            assert other_status["trace_id"] != request_a

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
