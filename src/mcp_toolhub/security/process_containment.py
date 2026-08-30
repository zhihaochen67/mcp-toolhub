"""OS-backed process-tree containment for ToolHub child processes.

The public entry point in this module launches exactly one absolute executable
with ``shell=False``.  stdout/stderr are binary pipes continuously drained by
dedicated bounded reader threads from the moment the process starts (see
``mcp_toolhub.security.bounded_output``), so output collection memory is O(1)
in produced volume and a noisy contained descendant can never fill an OS pipe
buffer and deadlock.  POSIX children run in a new session/process group.
Windows children are created suspended, assigned to a per-execution Job Object
configured with kill-on-close, and only then resumed.

This boundary intentionally contains process lifetime and output capture
memory only.  It is not a filesystem, network, or resource-usage sandbox.
"""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mcp_toolhub.security.bounded_output import CaptureStats, OutputCapture

PROCESS_CONTAINMENT_POLICY_VERSION = 1

_GRACEFUL_TERMINATION_SECONDS = 0.5
_FORCED_TERMINATION_SECONDS = 2.0
_FINAL_REAP_SECONDS = 1.0
_POLL_INTERVAL_SECONDS = 0.01
_MAX_DIAGNOSTIC_CHARS = 300
_DRAIN_EOF_WAIT_SECONDS = 1.0
_DRAIN_JOIN_SECONDS = 1.0

_WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_WINDOWS_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_WINDOWS_TERMINATION_EXIT_CODE = 1
_WINDOWS_CREATE_SUSPENDED = 0x00000004


@dataclass
class ContainmentMetadata:
    """Bounded, non-sensitive containment lifecycle metadata."""

    platform: str
    mechanism: str
    tree_termination_attempted: bool = False
    tree_termination_succeeded: bool = True

    def audit_metadata(self) -> dict[str, object]:
        return {
            "policy_version": PROCESS_CONTAINMENT_POLICY_VERSION,
            "platform": self.platform,
            "mechanism": self.mechanism,
            "tree_termination_attempted": self.tree_termination_attempted,
            "tree_termination_succeeded": self.tree_termination_succeeded,
        }


_EMPTY_CAPTURE_STATS = CaptureStats()


@dataclass(frozen=True)
class ContainedProcessResult:
    """Captured outcome of one contained external execution."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cleanup_error: str | None
    containment: ContainmentMetadata
    stdout_stats: CaptureStats = _EMPTY_CAPTURE_STATS
    stderr_stats: CaptureStats = _EMPTY_CAPTURE_STATS

    def capture_audit_metadata(self) -> dict[str, object]:
        """Return safe numeric/boolean capture accounting for audit."""
        return {
            "stdout_total_bytes": self.stdout_stats.total_bytes,
            "stdout_retained_bytes": self.stdout_stats.retained_bytes,
            "stdout_dropped_bytes": self.stdout_stats.dropped_bytes,
            "stdout_truncated": self.stdout_stats.truncated,
            "stderr_total_bytes": self.stderr_stats.total_bytes,
            "stderr_retained_bytes": self.stderr_stats.retained_bytes,
            "stderr_dropped_bytes": self.stderr_stats.dropped_bytes,
            "stderr_truncated": self.stderr_stats.truncated,
        }


class ProcessContainmentError(RuntimeError):
    """Containment setup or cleanup failed after the launch boundary."""

    def __init__(
        self,
        message: str,
        *,
        launched: bool,
        containment: ContainmentMetadata,
    ) -> None:
        super().__init__(_bounded_diagnostic(message))
        self.launched = launched
        self.containment = containment


def containment_policy_metadata() -> ContainmentMetadata:
    """Return metadata for the mechanism selected on this platform."""

    if os.name == "nt":
        return ContainmentMetadata("windows", "job_object")
    return ContainmentMetadata("posix", "session_process_group")


def _bounded_diagnostic(value: object) -> str:
    text = str(value).replace("\x00", "")
    if len(text) <= _MAX_DIAGNOSTIC_CHARS:
        return text
    return text[:_MAX_DIAGNOSTIC_CHARS] + "...[truncated]"


def _popen(
    executable: str,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    start_new_session: bool = False,
    creationflags: int = 0,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [executable, *args],
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        shell=False,
        close_fds=True,
        start_new_session=start_new_session,
        creationflags=creationflags,
    )


def _start_capture(process: subprocess.Popen[bytes]) -> OutputCapture:
    """Start both bounded drain threads over the launched binary pipes."""
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Contained process capture pipes are unavailable.")
    return OutputCapture(process.stdout, process.stderr)


def _close_process_pipes_without_readers(process: subprocess.Popen[bytes]) -> None:
    """Close capture pipes only when no drain thread can exist."""
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _wait_primary(process: subprocess.Popen[bytes], timeout: float) -> bool:
    if process.returncode is not None:
        return True
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def _finalize_capture(
    capture: OutputCapture,
    cleanup_errors: list[str],
) -> bool:
    """Finish one execution's output drains with bounded waits.

    After the contained tree has exited (or been terminated), give the drain
    threads a short interval to observe EOF.  If pipes remain open — a writer
    outside the contained tree keeping inherited handles — signal the
    non-blocking readers to stop, then bounded-join them.  Pipe handles are
    closed only after their readers finish.  Returns ``True`` only when both
    drains reached EOF without error.
    """
    if not capture.wait_for_eof(_DRAIN_EOF_WAIT_SECONDS):
        capture.close_streams()
    finished, drain_error = capture.join_readers(_DRAIN_JOIN_SECONDS)
    if drain_error:
        cleanup_errors.append(drain_error)
    return finished and drain_error is None


def _posix_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_posix_group(process_group: int, selected_signal: signal.Signals) -> bool:
    if process_group == os.getpgrp():
        raise RuntimeError("Refused to signal ToolHub's own process group.")
    try:
        os.killpg(process_group, selected_signal)
    except ProcessLookupError:
        return False
    return True


def _wait_for_posix_group_exit(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _posix_group_exists(process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))
    return True


def _terminate_posix_tree(
    process_group: int,
    metadata: ContainmentMetadata,
    cleanup_errors: list[str],
) -> None:
    """TERM -> KILL one isolated POSIX session/process group.

    Uses the existing bounded waits.  The drain reader threads keep consuming
    output concurrently throughout, so no extra output handling happens here.
    """

    try:
        if _signal_posix_group(process_group, signal.SIGTERM):
            metadata.tree_termination_attempted = True
    except OSError as exc:
        cleanup_errors.append(f"Graceful process-group termination failed: {exc}")

    try:
        group_remains = not _wait_for_posix_group_exit(
            process_group,
            _GRACEFUL_TERMINATION_SECONDS,
        )
    except OSError as exc:
        group_remains = True
        cleanup_errors.append(f"Process-group state check failed: {exc}")

    if group_remains:
        try:
            if _signal_posix_group(process_group, signal.SIGKILL):
                metadata.tree_termination_attempted = True
        except OSError as exc:
            cleanup_errors.append(f"Forced process-group termination failed: {exc}")

        try:
            _wait_for_posix_group_exit(process_group, _FORCED_TERMINATION_SECONDS)
        except OSError as exc:
            cleanup_errors.append(f"Forced process-group exit check failed: {exc}")


def _run_posix(
    executable: str,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> ContainedProcessResult:
    metadata = containment_policy_metadata()
    process = _popen(
        executable,
        args,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    process_group = process.pid
    capture: OutputCapture | None = None
    timed_out = False
    cleanup_errors: list[str] = []
    communication_complete = False

    try:
        capture = _start_capture(process)
        primary_done = _wait_primary(process, timeout_seconds)
        if not primary_done:
            timed_out = True

        try:
            group_remains = _posix_group_exists(process_group)
        except OSError as exc:
            group_remains = True
            cleanup_errors.append(f"Process-group state check failed: {exc}")

        if timed_out or group_remains:
            _terminate_posix_tree(process_group, metadata, cleanup_errors)

        communication_complete = _finalize_capture(capture, cleanup_errors)

        primary_reaped = _wait_primary(process, _FINAL_REAP_SECONDS)
        try:
            group_gone = not _posix_group_exists(process_group)
        except OSError as exc:
            group_gone = False
            cleanup_errors.append(f"Final process-group state check failed: {exc}")

        if not primary_reaped:
            cleanup_errors.append(
                "Primary process could not be reaped within the bound."
            )
        if not group_gone:
            cleanup_errors.append("Contained process group remained active.")

        succeeded = (
            primary_reaped
            and group_gone
            and communication_complete
            and not cleanup_errors
        )
        metadata.tree_termination_succeeded = succeeded
        if not succeeded and not timed_out:
            raise ProcessContainmentError(
                _bounded_diagnostic(" ".join(cleanup_errors))
                or "Contained process-tree cleanup failed.",
                launched=True,
                containment=metadata,
            )

        stdout, stderr = capture.text()
        stdout_stats, stderr_stats = capture.stats()
        cleanup_error = (
            _bounded_diagnostic(" ".join(cleanup_errors)) if cleanup_errors else None
        )
        return ContainedProcessResult(
            process.returncode,
            stdout,
            stderr,
            timed_out,
            cleanup_error,
            metadata,
            stdout_stats,
            stderr_stats,
        )
    except ProcessContainmentError:
        raise
    except BaseException as exc:
        _terminate_posix_tree(process_group, metadata, cleanup_errors)
        if capture is not None:
            _finalize_capture(capture, cleanup_errors)
        _wait_primary(process, _FINAL_REAP_SECONDS)
        if not isinstance(exc, Exception):
            raise
        diagnostic = "Contained process execution failed."
        if cleanup_errors:
            diagnostic += " " + " ".join(cleanup_errors)
        raise ProcessContainmentError(
            diagnostic,
            launched=True,
            containment=metadata,
        ) from exc
    finally:
        if capture is not None:
            capture.close_streams()
        else:
            _close_process_pipes_without_readers(process)


class _WindowsJobApi(Protocol):
    def create_job(self) -> int: ...

    def configure_kill_on_close(self, job_handle: int) -> None: ...

    def assign_process(self, job_handle: int, process_handle: int) -> None: ...

    def resume_process(self, process_handle: int) -> None: ...

    def terminate_job(self, job_handle: int) -> None: ...

    def active_processes(self, job_handle: int) -> int: ...

    def close_handle(self, handle: int) -> None: ...


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_ulong),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_ulong),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_ulong),
        ("SchedulingClass", ctypes.c_ulong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobObjectBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", ctypes.c_ulong),
        ("TotalProcesses", ctypes.c_ulong),
        ("ActiveProcesses", ctypes.c_ulong),
        ("TotalTerminatedProcesses", ctypes.c_ulong),
    ]


class _NativeWindowsJobApi:
    """Checked ctypes bindings for Windows Job Object operations."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are unavailable on this platform.")

        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        handle = ctypes.c_void_p
        dword = ctypes.c_ulong
        boolean = ctypes.c_int

        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._kernel32.CreateJobObjectW.restype = handle
        self._kernel32.SetInformationJobObject.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            dword,
        ]
        self._kernel32.SetInformationJobObject.restype = boolean
        self._kernel32.AssignProcessToJobObject.argtypes = [handle, handle]
        self._kernel32.AssignProcessToJobObject.restype = boolean
        self._kernel32.TerminateJobObject.argtypes = [handle, dword]
        self._kernel32.TerminateJobObject.restype = boolean
        self._kernel32.QueryInformationJobObject.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            dword,
            ctypes.POINTER(dword),
        ]
        self._kernel32.QueryInformationJobObject.restype = boolean
        self._kernel32.CloseHandle.argtypes = [handle]
        self._kernel32.CloseHandle.restype = boolean
        self._ntdll.NtResumeProcess.argtypes = [handle]
        self._ntdll.NtResumeProcess.restype = ctypes.c_long

    @staticmethod
    def _handle(value: int) -> ctypes.c_void_p:
        return ctypes.c_void_p(value)

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error_code = ctypes.get_last_error()
        raise OSError(error_code, f"{operation} failed")

    def create_job(self) -> int:
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            self._raise_last_error("CreateJobObjectW")
        return int(handle)

    def configure_kill_on_close(self, job_handle: int) -> None:
        information = _JobObjectExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = (
            _WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not self._kernel32.SetInformationJobObject(
            self._handle(job_handle),
            _WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            self._raise_last_error("SetInformationJobObject")

    def assign_process(self, job_handle: int, process_handle: int) -> None:
        if not self._kernel32.AssignProcessToJobObject(
            self._handle(job_handle),
            self._handle(process_handle),
        ):
            self._raise_last_error("AssignProcessToJobObject")

    def resume_process(self, process_handle: int) -> None:
        status = self._ntdll.NtResumeProcess(self._handle(process_handle))
        if status != 0:
            raise OSError(status, "NtResumeProcess failed")

    def terminate_job(self, job_handle: int) -> None:
        if not self._kernel32.TerminateJobObject(
            self._handle(job_handle),
            _WINDOWS_TERMINATION_EXIT_CODE,
        ):
            self._raise_last_error("TerminateJobObject")

    def active_processes(self, job_handle: int) -> int:
        information = _JobObjectBasicAccountingInformation()
        if not self._kernel32.QueryInformationJobObject(
            self._handle(job_handle),
            _WINDOWS_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
            None,
        ):
            self._raise_last_error("QueryInformationJobObject")
        return int(information.ActiveProcesses)

    def close_handle(self, handle: int) -> None:
        if not self._kernel32.CloseHandle(self._handle(handle)):
            self._raise_last_error("CloseHandle")


class _WindowsJob:
    """One kill-on-close Windows Job Object with deterministic ownership."""

    def __init__(self, api: _WindowsJobApi, handle: int) -> None:
        self._api = api
        self._handle: int | None = handle
        self.assigned = False

    @classmethod
    def create(cls, api: _WindowsJobApi | None = None) -> _WindowsJob:
        selected_api = api or _NativeWindowsJobApi()
        handle = selected_api.create_job()
        try:
            selected_api.configure_kill_on_close(handle)
        except BaseException:
            selected_api.close_handle(handle)
            raise
        return cls(selected_api, handle)

    def _required_handle(self) -> int:
        if self._handle is None:
            raise RuntimeError("Windows Job Object handle is already closed.")
        return self._handle

    def assign_and_resume(self, process_handle: int) -> None:
        handle = self._required_handle()
        self._api.assign_process(handle, process_handle)
        self.assigned = True
        self._api.resume_process(process_handle)

    def terminate(self) -> None:
        self._api.terminate_job(self._required_handle())

    def active_processes(self) -> int:
        return self._api.active_processes(self._required_handle())

    def close(self) -> None:
        if self._handle is None:
            return
        handle = self._handle
        self._handle = None
        self._api.close_handle(handle)


def _windows_process_handle(process: subprocess.Popen[bytes]) -> int:
    handle = getattr(process, "_handle", None)
    if handle is None:
        raise OSError("Windows process handle is unavailable.")
    return int(handle)


def _close_windows_process_handle(process: subprocess.Popen[bytes]) -> None:
    handle = getattr(process, "_handle", None)
    close = getattr(handle, "Close", None)
    if close is not None:
        close()


def _wait_for_windows_job_exit(job: _WindowsJob, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while job.active_processes() != 0:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))
    return True


def _abort_unassigned_windows_process(
    process: subprocess.Popen[bytes],
    capture: OutputCapture | None,
    cleanup_errors: list[str],
) -> None:
    try:
        process.terminate()
    except OSError:
        pass
    if capture is not None:
        _finalize_capture(capture, cleanup_errors)
    _wait_primary(process, _FINAL_REAP_SECONDS)
    if capture is None:
        _close_process_pipes_without_readers(process)


def _run_windows(
    executable: str,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> ContainedProcessResult:
    metadata = containment_policy_metadata()
    job = _WindowsJob.create()
    process: subprocess.Popen[bytes] | None = None
    capture: OutputCapture | None = None
    timed_out = False
    cleanup_errors: list[str] = []
    communication_complete = False

    try:
        process = _popen(
            executable,
            args,
            cwd=cwd,
            env=env,
            creationflags=_WINDOWS_CREATE_SUSPENDED,
        )
        capture = _start_capture(process)
        try:
            job.assign_and_resume(_windows_process_handle(process))
        except BaseException:
            if not job.assigned:
                _abort_unassigned_windows_process(process, capture, cleanup_errors)
            raise

        primary_done = _wait_primary(process, timeout_seconds)
        if not primary_done:
            timed_out = True

        try:
            active_processes = job.active_processes()
        except OSError as exc:
            active_processes = 1
            cleanup_errors.append(f"Job Object state check failed: {exc}")

        if timed_out or active_processes:
            metadata.tree_termination_attempted = True
            try:
                job.terminate()
            except OSError as exc:
                cleanup_errors.append(f"Job Object termination failed: {exc}")
            try:
                job_empty = _wait_for_windows_job_exit(
                    job,
                    _FINAL_REAP_SECONDS,
                )
            except OSError as exc:
                job_empty = False
                cleanup_errors.append(f"Job Object exit check failed: {exc}")
        else:
            job_empty = True

        communication_complete = _finalize_capture(capture, cleanup_errors)

    except BaseException as exc:
        if process is not None and job.assigned:
            metadata.tree_termination_attempted = True
            try:
                job.terminate()
            except OSError as cleanup_exc:
                cleanup_errors.append(f"Job Object termination failed: {cleanup_exc}")
        elif process is not None and capture is None:
            _abort_unassigned_windows_process(process, None, cleanup_errors)
        if capture is not None:
            _finalize_capture(capture, cleanup_errors)
        if not isinstance(exc, Exception):
            raise
        if process is None and isinstance(exc, OSError):
            raise
        diagnostic = "Contained Windows process setup or execution failed."
        if cleanup_errors:
            diagnostic += " " + " ".join(cleanup_errors)
        raise ProcessContainmentError(
            diagnostic,
            launched=process is not None,
            containment=metadata,
        ) from exc
    finally:
        if capture is not None:
            capture.close_streams()
        elif process is not None:
            _close_process_pipes_without_readers(process)
        try:
            job.close()
        except OSError as exc:
            cleanup_errors.append(f"Job Object handle close failed: {exc}")
        if process is not None:
            _wait_primary(process, _FINAL_REAP_SECONDS)
            _close_windows_process_handle(process)

    if process is None or capture is None:
        raise RuntimeError("Contained Windows launch did not create a process.")

    primary_reaped = process.returncode is not None
    succeeded = (
        primary_reaped and job_empty and communication_complete and not cleanup_errors
    )
    metadata.tree_termination_succeeded = succeeded
    if not primary_reaped:
        cleanup_errors.append("Primary process could not be reaped within the bound.")
    if not job_empty:
        cleanup_errors.append("Contained Job Object remained active.")

    cleanup_error = (
        _bounded_diagnostic(" ".join(cleanup_errors)) if cleanup_errors else None
    )
    if not succeeded and not timed_out:
        raise ProcessContainmentError(
            cleanup_error or "Contained process-tree cleanup failed.",
            launched=True,
            containment=metadata,
        )

    stdout, stderr = capture.text()
    stdout_stats, stderr_stats = capture.stats()
    return ContainedProcessResult(
        process.returncode,
        stdout,
        stderr,
        timed_out,
        cleanup_error,
        metadata,
        stdout_stats,
        stderr_stats,
    )


def run_contained_process(
    executable: str | os.PathLike[str],
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> ContainedProcessResult:
    """Launch one absolute executable inside an OS-backed tree boundary."""

    selected_executable = os.fspath(executable)
    if not Path(selected_executable).is_absolute():
        raise ValueError("Contained executable path must be absolute.")
    if timeout_seconds <= 0:
        raise ValueError("Contained process timeout must be positive.")

    if os.name == "nt":
        return _run_windows(
            selected_executable,
            args,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
        )
    return _run_posix(
        selected_executable,
        args,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
    )
