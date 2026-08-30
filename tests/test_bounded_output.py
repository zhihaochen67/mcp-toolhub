"""Focused tests for bounded output capture in contained subprocesses.

These tests prove that stdout/stderr collection is memory-bounded at the
containment layer: retained output never exceeds ``MAX_CAPTURE_BYTES_PER_STREAM``
while the pipes are still drained to EOF, truncation never changes success or
non-zero exit semantics, and reader failures are surfaced rather than silently
dropped.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from mcp_toolhub.contracts import ContractOutcome
from mcp_toolhub.observability import audit
from mcp_toolhub.security import approval
from mcp_toolhub.security.bounded_output import (
    MAX_CAPTURE_BYTES_PER_STREAM,
    OutputCapture,
    _close_pipe,
    _StreamCapture,
)
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.process_containment import (
    ProcessContainmentError,
    _finalize_capture,
    run_contained_process,
)
from mcp_toolhub.tools.git import GIT_MAX_OUTPUT_CHARS, git_diff
from mcp_toolhub.tools.shell import (
    MAX_OUTPUT_CHARS,
    _format_captured_output,
    run_approved_shell,
    run_shell,
)

_MEGABYTE = 1024 * 1024


def _run_python(program: str, *, cwd: Path, timeout_seconds: float = 15.0):
    return run_contained_process(
        sys.executable,
        ["-c", program],
        cwd=cwd,
        env=build_execution_environment().environment(),
        timeout_seconds=timeout_seconds,
    )


def _assert_bounded(stats) -> None:
    assert stats.truncated is True
    assert stats.dropped_bytes > 0
    assert stats.retained_bytes <= MAX_CAPTURE_BYTES_PER_STREAM
    assert stats.total_bytes == stats.retained_bytes + stats.dropped_bytes


def _raw_pipe() -> tuple[object, int]:
    read_descriptor, write_descriptor = os.pipe()
    return os.fdopen(read_descriptor, "rb", buffering=0), write_descriptor


def _open_pipe_capture() -> tuple[OutputCapture, tuple[int, int]]:
    stdout, stdout_writer = _raw_pipe()
    stderr, stderr_writer = _raw_pipe()
    try:
        return OutputCapture(stdout, stderr), (stdout_writer, stderr_writer)
    except BaseException:
        os.close(stdout_writer)
        os.close(stderr_writer)
        raise


def _close_writers(writers: tuple[int, int]) -> None:
    for descriptor in writers:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _wait_until(predicate, *, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail("Timed out waiting for bounded output reader state.")
        time.sleep(min(0.005, remaining))


def test_huge_stdout_is_bounded_in_memory(temp_dir):
    emitted = 4 * _MEGABYTE
    result = _run_python(
        f"import sys; "
        f"sys.stdout.buffer.write(b'x' * {emitted}); sys.stdout.buffer.flush()",
        cwd=temp_dir,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_error is None

    stats = result.stdout_stats
    _assert_bounded(stats)
    assert stats.total_bytes == emitted
    assert len(result.stdout) <= MAX_CAPTURE_BYTES_PER_STREAM
    assert result.stdout == "x" * stats.retained_bytes

    assert result.stderr_stats.truncated is False
    assert result.stderr_stats.total_bytes == 0
    assert result.stderr == ""


def test_huge_stderr_is_independently_bounded(temp_dir):
    emitted = 4 * _MEGABYTE
    result = _run_python(
        f"import sys; "
        f"sys.stderr.buffer.write(b'y' * {emitted}); sys.stderr.buffer.flush()",
        cwd=temp_dir,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_error is None

    stats = result.stderr_stats
    _assert_bounded(stats)
    assert stats.total_bytes == emitted
    assert len(result.stderr) <= MAX_CAPTURE_BYTES_PER_STREAM
    assert result.stderr == "y" * stats.retained_bytes

    assert result.stdout_stats.truncated is False
    assert result.stdout_stats.total_bytes == 0
    assert result.stdout == ""


def test_multiple_megabytes_on_both_streams_concurrently(temp_dir):
    # Stress/regression: both pipes receive several MB at once, well beyond
    # OS pipe capacity; sequential capture would deadlock here.
    emitted = 3 * _MEGABYTE
    program = (
        "import sys\n"
        "chunk = b'z' * 65536\n"
        f"for _ in range({emitted // 65536}):\n"
        "    sys.stdout.buffer.write(chunk)\n"
        "    sys.stderr.buffer.write(chunk)\n"
        "    sys.stdout.buffer.flush()\n"
        "    sys.stderr.buffer.flush()\n"
    )
    result = _run_python(program, cwd=temp_dir)

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_error is None

    for stats in (result.stdout_stats, result.stderr_stats):
        _assert_bounded(stats)
        assert stats.total_bytes == emitted
    assert result.stdout == "z" * result.stdout_stats.retained_bytes
    assert result.stderr == "z" * result.stderr_stats.retained_bytes


def test_huge_output_without_newline_is_bounded(temp_dir):
    emitted = 4 * _MEGABYTE
    result = _run_python(
        f"import sys; sys.stdout.buffer.write(b'n' * {emitted}); "
        f"sys.stdout.buffer.flush()",
        cwd=temp_dir,
    )

    assert result.returncode == 0
    _assert_bounded(result.stdout_stats)
    assert result.stdout == "n" * result.stdout_stats.retained_bytes
    assert "\n" not in result.stdout


def test_asymmetric_output_is_bounded_per_stream(temp_dir):
    huge_stdout_tiny_stderr = _run_python(
        "import sys; "
        f"sys.stdout.buffer.write(b'o' * {4 * _MEGABYTE}); sys.stdout.buffer.flush(); "
        "sys.stderr.write('tiny-err'); sys.stderr.flush()",
        cwd=temp_dir,
    )
    assert huge_stdout_tiny_stderr.returncode == 0
    assert huge_stdout_tiny_stderr.cleanup_error is None
    _assert_bounded(huge_stdout_tiny_stderr.stdout_stats)
    assert huge_stdout_tiny_stderr.stderr == "tiny-err"
    assert huge_stdout_tiny_stderr.stderr_stats.truncated is False
    assert huge_stdout_tiny_stderr.stderr_stats.total_bytes == len(b"tiny-err")

    tiny_stdout_huge_stderr = _run_python(
        "import sys; "
        "sys.stdout.write('tiny-out'); sys.stdout.flush(); "
        f"sys.stderr.buffer.write(b'e' * {4 * _MEGABYTE}); sys.stderr.buffer.flush()",
        cwd=temp_dir,
    )
    assert tiny_stdout_huge_stderr.returncode == 0
    assert tiny_stdout_huge_stderr.cleanup_error is None
    assert tiny_stdout_huge_stderr.stdout == "tiny-out"
    assert tiny_stdout_huge_stderr.stdout_stats.truncated is False
    _assert_bounded(tiny_stdout_huge_stderr.stderr_stats)


def test_output_larger_than_os_pipe_capacity_completes(temp_dir):
    # 512 KiB exceeds typical OS pipe capacity (8-64 KiB) while staying cheap.
    emitted = 512 * 1024
    result = _run_python(
        f"import sys; sys.stdout.buffer.write(b'p' * {emitted}); "
        f"sys.stdout.buffer.flush()",
        cwd=temp_dir,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_error is None
    _assert_bounded(result.stdout_stats)


def test_descendant_inheriting_pipes_with_huge_output_times_out_bounded(temp_dir):
    writer = (
        "import sys\n"
        "while True:\n"
        "    sys.stdout.buffer.write(b'w' * 65536)\n"
        "    sys.stderr.buffer.write(b'w' * 65536)\n"
        "    sys.stdout.buffer.flush()\n"
        "    sys.stderr.buffer.flush()\n"
    )
    parent = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {writer!r}], "
        "stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stderr)\n"
        "time.sleep(60)\n"
    )
    started = time.monotonic()
    result = _run_python(parent, cwd=temp_dir, timeout_seconds=1.0)

    assert result.timed_out is True
    assert result.cleanup_error is None
    assert result.containment.tree_termination_attempted is True
    assert result.containment.tree_termination_succeeded is True
    _assert_bounded(result.stdout_stats)
    _assert_bounded(result.stderr_stats)
    assert result.stdout == "w" * result.stdout_stats.retained_bytes
    assert result.stderr == "w" * result.stderr_stats.retained_bytes
    assert time.monotonic() - started < 15


def test_timeout_after_huge_output_returns_timed_out_bounded(temp_dir):
    program = (
        "import sys; "
        f"sys.stdout.buffer.write(b't' * {8 * _MEGABYTE}); sys.stdout.buffer.flush(); "
        "import time; time.sleep(60)"
    )
    started = time.monotonic()
    result = _run_python(program, cwd=temp_dir, timeout_seconds=1.0)

    assert result.timed_out is True
    assert result.cleanup_error is None
    assert result.containment.tree_termination_attempted is True
    assert result.containment.tree_termination_succeeded is True
    _assert_bounded(result.stdout_stats)
    assert len(result.stdout) <= MAX_CAPTURE_BYTES_PER_STREAM
    assert result.stdout == "t" * result.stdout_stats.retained_bytes
    assert time.monotonic() - started < 15


def test_small_output_is_byte_for_byte_compatible(temp_dir):
    stdout_bytes = "héllo wörld ☃\n".encode()
    stderr_bytes = "warn: naïve\n".encode()
    result = _run_python(
        "import sys; "
        f"sys.stdout.buffer.write({stdout_bytes!r}); "
        f"sys.stderr.buffer.write({stderr_bytes!r}); "
        "sys.stdout.buffer.flush(); sys.stderr.buffer.flush()",
        cwd=temp_dir,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_error is None
    assert result.stdout == stdout_bytes.decode("utf-8")
    assert result.stderr == stderr_bytes.decode("utf-8")
    assert result.stdout_stats.truncated is False
    assert result.stdout_stats.dropped_bytes == 0
    assert result.stdout_stats.retained_bytes == len(stdout_bytes)
    assert result.stdout_stats.total_bytes == len(stdout_bytes)
    assert result.stderr_stats.truncated is False
    assert result.stderr_stats.dropped_bytes == 0
    assert result.stderr_stats.retained_bytes == len(stderr_bytes)


def test_nonzero_exit_result_semantics_unchanged(temp_dir):
    result = _run_python(
        "import sys; sys.stdout.write('partial-out'); "
        "sys.stderr.write('partial-err'); sys.exit(9)",
        cwd=temp_dir,
    )

    assert result.returncode == 9
    assert result.timed_out is False
    assert result.cleanup_error is None
    assert result.stdout == "partial-out"
    assert result.stderr == "partial-err"
    assert result.stdout_stats.truncated is False
    assert result.stderr_stats.truncated is False


def test_start_failure_is_unchanged(temp_dir):
    missing = temp_dir / "definitely-not-an-executable-1f3a"

    with pytest.raises(OSError):
        run_contained_process(
            str(missing),
            [],
            cwd=temp_dir,
            env=build_execution_environment().environment(),
            timeout_seconds=5,
        )


def test_approved_shell_huge_output_remains_succeeded_with_marker():
    program = (
        "import sys; "
        f"sys.stdout.buffer.write(b's' * {2 * _MEGABYTE}); sys.stdout.buffer.flush()"
    )
    created = run_shell(sys.executable, ["-c", program])
    approval.approve_request(created.request_id)

    result = run_approved_shell(created.request_id)

    assert result.outcome == ContractOutcome.SUCCEEDED
    assert result.returncode == 0
    assert result.stdout.startswith("s" * MAX_OUTPUT_CHARS)
    assert "\n\n[ToolHub discarded " in result.stdout
    assert result.stdout.endswith(" output bytes]")
    assert len(result.stdout) <= MAX_OUTPUT_CHARS + 64
    assert result.stderr == ""


def test_approved_shell_audit_capture_metadata_is_bounded():
    created = run_shell(sys.executable, ["-c", "print('audit-capture-ok')"])
    approval.approve_request(created.request_id)

    result = run_approved_shell(created.request_id)
    assert result.outcome == ContractOutcome.SUCCEEDED

    event = audit.read_recent(limit=100)[-1]
    capture = event["extra"]["capture"]
    assert set(capture) == {
        "stdout_total_bytes",
        "stdout_retained_bytes",
        "stdout_dropped_bytes",
        "stdout_truncated",
        "stderr_total_bytes",
        "stderr_retained_bytes",
        "stderr_dropped_bytes",
        "stderr_truncated",
    }
    # Byte counts are raw captured bytes (platform line endings); the
    # character count reflects the universal-newline-translated text.
    expected_bytes = len(f"audit-capture-ok{os.linesep}".encode())
    assert capture["stdout_total_bytes"] == expected_bytes
    assert capture["stdout_retained_bytes"] == expected_bytes
    assert capture["stdout_dropped_bytes"] == 0
    assert capture["stdout_truncated"] is False
    assert capture["stderr_total_bytes"] == 0
    # Audit must never contain raw process output, only bounded counts.
    assert event["stdout_chars"] == len("audit-capture-ok\n")
    assert "error" not in event


def test_git_diff_output_is_bounded(git_repo):
    # Many small lines produce a diff well beyond the capture cap without
    # creating hundreds of MB: ~20k lines yields a >400 KiB diff.
    lines = [f"line {index}\n" for index in range(20_000)]
    path = git_repo / "a.txt"
    path.write_text("".join(lines), encoding="utf-8")
    subprocess.run(
        ["git", "add", "a.txt"],
        cwd=str(git_repo),
        capture_output=True,
        text=True,
        check=True,
    )
    modified = [f"line {index} changed\n" for index in range(20_000)]
    path.write_text("".join(modified), encoding="utf-8")

    result = git_diff(root=git_repo)

    assert result.binary is False
    # The retained prefix covers the start of the hunk; git emits deletions
    # before additions, so assert the aggregate rather than each side.
    assert result.additions + result.deletions > 0
    assert result.raw.startswith("diff --git")
    assert "output bytes discarded" in result.raw
    assert len(result.raw) <= GIT_MAX_OUTPUT_CHARS + 64


def test_shell_output_formatting_preserves_legacy_and_adds_discard_marker():
    value = "a" * (MAX_OUTPUT_CHARS + 7)
    formatted = _format_captured_output(
        value,
        capture_truncated=False,
        dropped_bytes=0,
    )
    assert formatted == value[:MAX_OUTPUT_CHARS] + (
        "\n\n[ToolHub truncated 7 characters]"
    )

    retained = "b" * (MAX_OUTPUT_CHARS + 40)
    formatted = _format_captured_output(
        retained,
        capture_truncated=True,
        dropped_bytes=1234,
    )
    assert formatted == (
        retained[:MAX_OUTPUT_CHARS] + "\n\n[ToolHub discarded 1274 output bytes]"
    )

    formatted = _format_captured_output(
        "short",
        capture_truncated=True,
        dropped_bytes=9,
    )
    assert formatted == "short\n\n[ToolHub discarded 9 output bytes]"


class _CloseFailingReader:
    def close(self):
        raise OSError("simulated close failure")


def test_stream_capture_retains_prefix_and_counts_dropped_bytes():
    half = MAX_CAPTURE_BYTES_PER_STREAM // 2
    capture = _StreamCapture(limit=MAX_CAPTURE_BYTES_PER_STREAM)
    capture.consume(b"a" * half)
    capture.consume(b"b" * MAX_CAPTURE_BYTES_PER_STREAM)
    capture.consume(b"tail")

    stats = capture.stats()
    assert stats.truncated is True
    assert stats.retained_bytes == MAX_CAPTURE_BYTES_PER_STREAM
    assert stats.total_bytes == half + MAX_CAPTURE_BYTES_PER_STREAM + 4
    assert stats.dropped_bytes == half + 4
    assert capture.text() == "a" * half + "b" * half


def test_utf8_split_boundary_decodes_deterministically_with_replacement():
    # "éé" is C3 A9 C3 A9; a 3-byte cap cuts inside the second character.
    capture = _StreamCapture(limit=3)
    capture.consume("éé".encode())

    stats = capture.stats()
    assert stats.truncated is True
    assert stats.total_bytes == 4
    assert stats.retained_bytes == 3
    assert stats.dropped_bytes == 1
    assert capture.text() == "é\ufffd"


def test_nonblocking_shutdown_stops_waiting_readers_with_writers_still_open():
    capture, writers = _open_pipe_capture()
    try:
        # These writer descriptors belong to the test process, outside any
        # contained process tree, and intentionally remain open through join.
        assert isinstance(capture._stdout_stream, io.FileIO)
        assert isinstance(capture._stderr_stream, io.FileIO)
        assert os.get_blocking(capture._stdout_stream.fileno()) is False
        assert os.get_blocking(capture._stderr_stream.fileno()) is False
        assert capture._stdout.waiting.wait(2.0) is True
        assert capture._stderr.waiting.wait(2.0) is True
        assert capture._stdout_thread.is_alive() is True
        assert capture._stderr_thread.is_alive() is True

        started = time.monotonic()
        capture.close_streams()
        close_elapsed = time.monotonic() - started
        finished, error = capture.join_readers(0.5)
        total_elapsed = time.monotonic() - started

        assert close_elapsed < 0.5
        assert total_elapsed < 1.0
        assert finished is False
        assert error is not None
        assert "stopped before EOF" in error
        assert capture._stdout_thread.is_alive() is False
        assert capture._stderr_thread.is_alive() is False
        assert capture._stdout_stream.closed is True
        assert capture._stderr_stream.closed is True
    finally:
        capture.close_streams()
        capture.join_readers(0.5)
        _close_writers(writers)


def test_finalize_capture_is_bounded_and_reports_missing_eof():
    from mcp_toolhub.security import process_containment

    capture, writers = _open_pipe_capture()
    raw_stdout = b"raw-output-must-not-enter-diagnostics"
    raw_stderr = b"raw-error-must-not-enter-diagnostics"
    try:
        os.write(writers[0], raw_stdout)
        os.write(writers[1], raw_stderr)
        _wait_until(
            lambda: (
                capture.stats()[0].total_bytes == len(raw_stdout)
                and capture.stats()[1].total_bytes == len(raw_stderr)
                and capture._stdout.waiting.is_set()
                and capture._stderr.waiting.is_set()
            )
        )
        cleanup_errors = []

        started = time.monotonic()
        complete = _finalize_capture(capture, cleanup_errors)
        elapsed = time.monotonic() - started

        finalization_bound = (
            process_containment._DRAIN_EOF_WAIT_SECONDS
            + process_containment._DRAIN_JOIN_SECONDS
            + 0.5
        )
        assert elapsed < finalization_bound
        assert complete is False
        assert cleanup_errors
        diagnostic = " ".join(cleanup_errors)
        assert "stopped before EOF" in diagnostic
        assert raw_stdout.decode() not in diagnostic
        assert raw_stderr.decode() not in diagnostic
        assert capture._stdout_thread.is_alive() is False
        assert capture._stderr_thread.is_alive() is False
    finally:
        capture.close_streams()
        capture.join_readers(0.5)
        _close_writers(writers)


def test_nonblocking_readers_preserve_normal_eof_behavior():
    capture, writers = _open_pipe_capture()
    try:
        os.write(writers[0], b"normal-out\r\n")
        os.write(writers[1], b"normal-err")
        _close_writers(writers)

        assert capture.wait_for_eof(2.0) is True
        finished, error = capture.join_readers(0.5)

        assert finished is True
        assert error is None
        assert capture.text() == ("normal-out\n", "normal-err")
        assert capture._stdout_thread.is_alive() is False
        assert capture._stderr_thread.is_alive() is False
    finally:
        capture.close_streams()
        capture.join_readers(0.5)
        _close_writers(writers)


def test_reader_exception_is_recorded_and_joinable(monkeypatch):
    from mcp_toolhub.security import bounded_output

    def failing_read(stream):
        raise OSError("simulated pipe read failure")

    monkeypatch.setattr(bounded_output, "_read_pipe_chunk", failing_read)
    capture, writers = _open_pipe_capture()
    try:
        assert capture.wait_for_eof(2.0) is False
        capture.close_streams()
        finished, error = capture.join_readers(0.5)

        assert finished is False
        assert error is not None
        assert "stdout drain failed" in error
        assert "simulated pipe read failure" in error
        assert capture._stdout_thread.is_alive() is False
        assert capture._stderr_thread.is_alive() is False
    finally:
        capture.close_streams()
        capture.join_readers(0.5)
        _close_writers(writers)


def test_close_pipe_swallows_close_errors():
    _close_pipe(_CloseFailingReader())  # must not raise


def test_reader_failure_is_fail_safe_without_thread_leak(temp_dir, monkeypatch):
    from mcp_toolhub.security import bounded_output

    calls = []

    def failing_drain(stream, capture, stop):
        calls.append(1)
        capture.error = "simulated drain failure"
        capture.done.set()

    monkeypatch.setattr(bounded_output, "_drain_stream", failing_drain)

    with pytest.raises(ProcessContainmentError) as captured:
        run_contained_process(
            sys.executable,
            ["-c", "print('unused-output')"],
            cwd=temp_dir,
            env=build_execution_environment().environment(),
            timeout_seconds=5,
        )

    assert captured.value.launched is True
    assert len(calls) == 2
    drain_threads = [
        thread
        for thread in threading.enumerate()
        if thread.name in {"toolhub-stdout-drain", "toolhub-stderr-drain"}
    ]
    assert drain_threads == []
