"""Focused OS-backed process-tree containment tests."""

from __future__ import annotations

import ctypes
import os
import select
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.process_containment import (
    PROCESS_CONTAINMENT_POLICY_VERSION,
    ProcessContainmentError,
    _WindowsJob,
    run_contained_process,
)


def _wait_for_pid(path: Path, *, timeout: float = 5.0) -> int:
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, OSError):
            value = ""
        if value.isdigit():
            return int(value)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail(f"Timed out waiting for child readiness file: {path.name}")
        time.sleep(min(0.01, remaining))


class _ProcessIdentity:
    """Stable short-lived identity probe resistant to ordinary PID reuse."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._handle: int | None = None
        self._pidfd: int | None = None
        self._proc_token: str | None = None

        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                ctypes.c_ulong,
                ctypes.c_int,
                ctypes.c_ulong,
            ]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            handle = kernel32.OpenProcess(0x00100000 | 0x00001000, False, pid)
            if not handle:
                raise OSError(ctypes.get_last_error(), "OpenProcess failed")
            self._handle = int(handle)
            return

        if hasattr(os, "pidfd_open"):
            self._pidfd = os.pidfd_open(pid)
            return

        stat_path = Path("/proc") / str(pid) / "stat"
        if stat_path.is_file():
            self._proc_token = stat_path.read_text(encoding="utf-8").split()[21]

    def is_running(self) -> bool:
        if self._handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel32.WaitForSingleObject.restype = ctypes.c_ulong
            return kernel32.WaitForSingleObject(self._handle, 0) == 0x00000102

        if self._pidfd is not None:
            readable, _writable, _errors = select.select([self._pidfd], [], [], 0)
            return not readable

        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        if self._proc_token is None:
            return True
        stat_path = Path("/proc") / str(self.pid) / "stat"
        try:
            current_token = stat_path.read_text(encoding="utf-8").split()[21]
        except (FileNotFoundError, IndexError, OSError):
            return False
        return current_token == self._proc_token

    def close(self) -> None:
        if self._handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            kernel32.CloseHandle(self._handle)
            self._handle = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None


def _wait_until_stopped(identity: _ProcessIdentity, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while identity.is_running():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail("Contained descendant remained alive after timeout cleanup.")
        time.sleep(min(0.01, remaining))


def _tree_program(pid_file: Path, *, grandchild: bool) -> list[str]:
    sleeper = "import time; time.sleep(60)"
    if grandchild:
        child = (
            "import subprocess,sys,time; from pathlib import Path; "
            f"p=subprocess.Popen([sys.executable,'-c',{sleeper!r}],"
            "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
            "Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii'); "
            "print('grandchild-ready',flush=True); time.sleep(60)"
        )
        parent = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{child!r},sys.argv[1]],"
            "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
            "time.sleep(60)"
        )
    else:
        parent = (
            "import subprocess,sys,time; from pathlib import Path; "
            f"p=subprocess.Popen([sys.executable,'-c',{sleeper!r}],"
            "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
            "Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii'); "
            "print('child-ready',flush=True); time.sleep(60)"
        )
    return ["-c", parent, str(pid_file)]


@pytest.mark.parametrize("grandchild", [False, True], ids=["child", "grandchild"])
def test_timeout_terminates_real_descendant_tree_and_inherited_pipes(
    temp_dir,
    grandchild,
):
    pid_file = temp_dir / ("grandchild.pid" if grandchild else "child.pid")
    environment = build_execution_environment().environment()
    started = time.monotonic()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            run_contained_process,
            sys.executable,
            _tree_program(pid_file, grandchild=grandchild),
            cwd=temp_dir,
            env=environment,
            timeout_seconds=1.5,
        )
        identity = _ProcessIdentity(_wait_for_pid(pid_file))
        try:
            assert identity.is_running()
            result = future.result(timeout=8)
            _wait_until_stopped(identity)
        finally:
            identity.close()

    assert result.timed_out is True
    assert result.cleanup_error is None
    assert result.containment.tree_termination_attempted is True
    assert result.containment.tree_termination_succeeded is True
    assert "ready" in result.stdout
    assert time.monotonic() - started < 7


def test_normal_and_nonzero_contained_commands_preserve_results(temp_dir):
    environment = build_execution_environment().environment()

    succeeded = run_contained_process(
        sys.executable,
        ["-c", "print('contained-ok')"],
        cwd=temp_dir,
        env=environment,
        timeout_seconds=5,
    )
    failed = run_contained_process(
        sys.executable,
        ["-c", "import sys; print('contained-failed'); sys.exit(7)"],
        cwd=temp_dir,
        env=environment,
        timeout_seconds=5,
    )

    assert succeeded.returncode == 0
    assert succeeded.stdout == "contained-ok\n"
    assert succeeded.timed_out is False
    assert failed.returncode == 7
    assert failed.stdout == "contained-failed\n"
    assert failed.timed_out is False


def test_successful_execution_does_not_terminate_unrelated_process(temp_dir):
    control = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        result = run_contained_process(
            sys.executable,
            ["-c", "print('done')"],
            cwd=temp_dir,
            env=build_execution_environment().environment(),
            timeout_seconds=5,
        )
        assert result.returncode == 0
        assert control.poll() is None
    finally:
        if control.poll() is None:
            control.terminate()
        control.wait(timeout=10)


def test_launch_is_absolute_shell_free_and_path_independent(temp_dir, monkeypatch):
    from mcp_toolhub.security import process_containment

    original_popen = process_containment.subprocess.Popen
    calls = []

    def spy_popen(command, **kwargs):
        calls.append((command, kwargs))
        return original_popen(command, **kwargs)

    monkeypatch.setattr(process_containment.subprocess, "Popen", spy_popen)
    environment = build_execution_environment().environment()
    result = run_contained_process(
        sys.executable,
        ["-c", "print('no-path')"],
        cwd=temp_dir,
        env=environment,
        timeout_seconds=5,
    )

    assert result.returncode == 0
    command, kwargs = calls[0]
    assert Path(command[0]).is_absolute()
    assert kwargs["shell"] is False
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.PIPE
    assert kwargs["env"] == environment
    assert "PATH" not in kwargs["env"]


def test_internal_exception_after_launch_still_reaps_process(temp_dir, monkeypatch):
    from mcp_toolhub.security import process_containment

    original_popen = process_containment.subprocess.Popen
    original_communicate = subprocess.Popen.communicate
    processes = []
    first_call = True

    def spy_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    def fail_once(self, *args, **kwargs):
        nonlocal first_call
        if first_call:
            first_call = False
            raise RuntimeError("simulated internal failure")
        return original_communicate(self, *args, **kwargs)

    monkeypatch.setattr(process_containment.subprocess, "Popen", spy_popen)
    monkeypatch.setattr(original_popen, "communicate", fail_once)

    with pytest.raises(ProcessContainmentError) as captured:
        run_contained_process(
            sys.executable,
            ["-c", "import time; time.sleep(60)"],
            cwd=temp_dir,
            env=build_execution_environment().environment(),
            timeout_seconds=5,
        )

    assert captured.value.launched is True
    assert processes[0].returncode is not None
    assert captured.value.containment.tree_termination_attempted is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group behavior")
def test_posix_timeout_signals_only_isolated_process_group(temp_dir, monkeypatch):
    from mcp_toolhub.security import process_containment

    original_killpg = os.killpg
    signals = []

    def spy_killpg(process_group, selected_signal):
        signals.append((process_group, selected_signal))
        return original_killpg(process_group, selected_signal)

    monkeypatch.setattr(process_containment.os, "killpg", spy_killpg)
    result = run_contained_process(
        sys.executable,
        ["-c", "import time; time.sleep(60)"],
        cwd=temp_dir,
        env={},
        timeout_seconds=0.2,
    )

    assert result.timed_out is True
    assert any(selected == signal.SIGTERM for _, selected in signals)
    assert all(group != os.getpgrp() for group, _ in signals)


class _FakeWindowsApi:
    def __init__(
        self,
        *,
        fail_configure: bool = False,
        fail_assign: bool = False,
    ) -> None:
        self.calls = []
        self.fail_configure = fail_configure
        self.fail_assign = fail_assign

    def create_job(self):
        self.calls.append(("create",))
        return 41

    def configure_kill_on_close(self, job_handle):
        self.calls.append(("configure", job_handle))
        if self.fail_configure:
            raise OSError("configure failed")

    def assign_process(self, job_handle, process_handle):
        self.calls.append(("assign", job_handle, process_handle))
        if self.fail_assign:
            raise OSError("assignment failed")

    def resume_process(self, process_handle):
        self.calls.append(("resume", process_handle))

    def terminate_job(self, job_handle):
        self.calls.append(("terminate", job_handle))

    def active_processes(self, job_handle):
        self.calls.append(("active", job_handle))
        return 0

    def close_handle(self, handle):
        self.calls.append(("close", handle))


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object behavior")
def test_windows_job_configures_assigns_before_resume_and_closes_once():
    api = _FakeWindowsApi()
    job = _WindowsJob.create(api)
    job.assign_and_resume(73)
    job.terminate()
    assert job.active_processes() == 0
    job.close()
    job.close()

    assert api.calls == [
        ("create",),
        ("configure", 41),
        ("assign", 41, 73),
        ("resume", 73),
        ("terminate", 41),
        ("active", 41),
        ("close", 41),
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object behavior")
def test_windows_job_setup_failure_closes_handle():
    api = _FakeWindowsApi(fail_configure=True)

    with pytest.raises(OSError, match="configure failed"):
        _WindowsJob.create(api)

    assert api.calls == [
        ("create",),
        ("configure", 41),
        ("close", 41),
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object behavior")
def test_windows_job_assignment_failure_never_resumes_process():
    api = _FakeWindowsApi(fail_assign=True)
    job = _WindowsJob.create(api)

    with pytest.raises(OSError, match="assignment failed"):
        job.assign_and_resume(73)
    job.close()

    assert job.assigned is False
    assert api.calls == [
        ("create",),
        ("configure", 41),
        ("assign", 41, 73),
        ("close", 41),
    ]


def test_containment_metadata_is_bounded_and_versioned(temp_dir):
    result = run_contained_process(
        sys.executable,
        ["-c", "pass"],
        cwd=temp_dir,
        env=build_execution_environment().environment(),
        timeout_seconds=5,
    )
    metadata = result.containment.audit_metadata()

    assert metadata["policy_version"] == PROCESS_CONTAINMENT_POLICY_VERSION == 1
    assert set(metadata) == {
        "policy_version",
        "platform",
        "mechanism",
        "tree_termination_attempted",
        "tree_termination_succeeded",
    }
