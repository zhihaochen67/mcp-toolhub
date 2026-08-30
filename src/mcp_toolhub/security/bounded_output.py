"""Bounded, continuously-drained capture for subprocess output pipes.

ToolHub launches external processes with raw, non-blocking binary stdout/stderr
pipes.  This module starts one dedicated drain thread per stream immediately
after launch.  Each thread reads fixed-size chunks until EOF and retains at most
``MAX_CAPTURE_BYTES_PER_STREAM`` bytes in a fixed-capacity buffer; any further
bytes are counted as dropped but still read from the pipe, so a noisy child or
contained descendant can never fill the OS pipe buffer and block itself (or
ToolHub) while output is being produced.

Design constraints
------------------
* Binary capture only: text decoding happens once, after collection, with
  UTF-8 ``errors="replace"``.
* No ``readline()`` (a stream may be one giant line) and no unbounded lists,
  queues, or bytearrays: retained memory is O(1) in the produced volume.
* At most two drain threads per subprocess.  Reads are non-blocking on both
  POSIX and Windows (supported for Windows pipes since Python 3.12), and an
  Event wakes each bounded polling wait during shutdown.  Reader threads are
  non-daemon and are expected to terminate, not abandoned at interpreter exit.
* Pipe objects are closed only after the corresponding reader has published
  completion, so the calling thread never races ``close()`` against ``read()``.
* A reader error is recorded on the capture and surfaced by the caller; a
  failed reader is never silent data loss.
"""

from __future__ import annotations

import io
import os
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO

MAX_CAPTURE_BYTES_PER_STREAM = 262_144  # 256 KiB retained per stdout/stderr
READ_CHUNK_BYTES = 64 * 1024

_DRAIN_ERROR_CHARS = 300
_READ_POLL_SECONDS = 0.01
_READER_START_JOIN_SECONDS = 1.0


@dataclass(frozen=True)
class CaptureStats:
    """Bounded per-stream capture accounting (integers/booleans only)."""

    total_bytes: int = 0
    retained_bytes: int = 0
    dropped_bytes: int = 0
    truncated: bool = False


def _drain_error_text(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    if len(text) <= _DRAIN_ERROR_CHARS:
        return text
    return text[:_DRAIN_ERROR_CHARS] + "...[truncated]"


class _StreamCapture:
    """Fixed-capacity retained buffer plus bounded counters for one stream."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._buffer = bytearray()
        self.total_bytes = 0
        self.dropped_bytes = 0
        self.truncated = False
        self.error: str | None = None
        self.eof = False
        self.waiting = threading.Event()
        self.done = threading.Event()

    def consume(self, chunk: bytes) -> None:
        size = len(chunk)
        self.total_bytes += size
        free = self._limit - len(self._buffer)
        if free >= size:
            self._buffer.extend(chunk)
            return
        if free > 0:
            self._buffer.extend(chunk[:free])
        self.dropped_bytes += size - free
        self.truncated = True

    def stats(self) -> CaptureStats:
        return CaptureStats(
            total_bytes=self.total_bytes,
            retained_bytes=len(self._buffer),
            dropped_bytes=self.dropped_bytes,
            truncated=self.truncated,
        )

    def text(self) -> str:
        # Decode only after collection and apply universal-newline
        # translation, exactly matching the previous text-mode pipe behavior
        # (``\r\n`` and lone ``\r`` become ``\n``) so small outputs remain
        # byte-for-byte compatible with the historical public result.
        return (
            bytes(self._buffer)
            .decode("utf-8", errors="replace")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
        )


def _set_nonblocking_pipe(stream: BinaryIO) -> None:
    """Require one raw pipe and put its descriptor in non-blocking mode."""
    if not isinstance(stream, io.FileIO):
        raise TypeError("Output capture requires a raw binary FileIO pipe.")
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    if os.get_blocking(descriptor):
        raise OSError("Output capture pipe remained in blocking mode.")


def _close_pipe(stream: BinaryIO) -> None:
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _read_pipe_chunk(stream: BinaryIO) -> bytes | None:
    """Perform one bounded non-blocking raw read."""
    return stream.read(READ_CHUNK_BYTES)


def _drain_stream(
    stream: BinaryIO,
    capture: _StreamCapture,
    stop: threading.Event,
) -> None:
    """Poll one non-blocking binary pipe, retaining at most the configured cap."""
    try:
        while not stop.is_set():
            try:
                chunk = _read_pipe_chunk(stream)
            except BlockingIOError:
                chunk = None

            if chunk == b"":
                capture.eof = True
                return
            if chunk is None:
                capture.waiting.set()
                try:
                    if stop.wait(_READ_POLL_SECONDS):
                        return
                finally:
                    capture.waiting.clear()
                continue
            capture.consume(chunk)
    except BaseException as exc:  # noqa: BLE001 - worker boundary; surfaced via capture.error
        capture.error = _drain_error_text(exc)
    finally:
        capture.waiting.clear()
        capture.done.set()


class OutputCapture:
    """Two bounded non-blocking drain threads over raw subprocess pipes."""

    def __init__(self, stdout_stream: BinaryIO, stderr_stream: BinaryIO) -> None:
        self._stdout_stream = stdout_stream
        self._stderr_stream = stderr_stream
        self._stdout = _StreamCapture(MAX_CAPTURE_BYTES_PER_STREAM)
        self._stderr = _StreamCapture(MAX_CAPTURE_BYTES_PER_STREAM)
        self._stop = threading.Event()

        try:
            _set_nonblocking_pipe(stdout_stream)
            _set_nonblocking_pipe(stderr_stream)
        except BaseException:
            # No reader exists yet, so these closes cannot contend with I/O.
            _close_pipe(stdout_stream)
            _close_pipe(stderr_stream)
            raise

        self._stdout_thread = threading.Thread(
            target=_drain_stream,
            args=(stdout_stream, self._stdout, self._stop),
            name="toolhub-stdout-drain",
            daemon=False,
        )
        self._stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(stderr_stream, self._stderr, self._stop),
            name="toolhub-stderr-drain",
            daemon=False,
        )
        try:
            self._stdout_thread.start()
            self._stderr_thread.start()
        except BaseException:
            self._stop.set()
            for thread in (self._stdout_thread, self._stderr_thread):
                if thread.ident is not None:
                    thread.join(_READER_START_JOIN_SECONDS)
            self._close_finished_streams()
            for stream, thread in (
                (self._stdout_stream, self._stdout_thread),
                (self._stderr_stream, self._stderr_thread),
            ):
                if thread.ident is None:
                    _close_pipe(stream)
            raise

    def wait_for_eof(self, timeout: float) -> bool:
        """Wait up to ``timeout`` for both readers to observe real EOF."""
        deadline = time.monotonic() + timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._stdout.done.wait(remaining):
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._stderr.done.wait(remaining):
            return False
        return self._stdout.eof and self._stderr.eof

    def join_readers(self, timeout: float) -> tuple[bool, str | None]:
        """Bounded-join both readers; report completion and any drain error."""
        deadline = time.monotonic() + timeout
        self._stdout_thread.join(max(0.0, deadline - time.monotonic()))
        self._stderr_thread.join(max(0.0, deadline - time.monotonic()))
        self._close_finished_streams()

        problems: list[str] = []
        if self._stdout_thread.is_alive():
            problems.append("stdout drain thread did not finish within the bound.")
        if self._stderr_thread.is_alive():
            problems.append("stderr drain thread did not finish within the bound.")
        for label, capture, thread in (
            ("stdout", self._stdout, self._stdout_thread),
            ("stderr", self._stderr, self._stderr_thread),
        ):
            if capture.error is not None:
                problems.append(f"{label} drain failed: {capture.error}")
            elif not thread.is_alive() and not capture.eof:
                problems.append(
                    f"{label} drain stopped before EOF during bounded shutdown."
                )
        if problems:
            return False, "; ".join(problems)
        return True, None

    def close_streams(self) -> None:
        """Request reader stop and close only pipes no reader can still use.

        Setting the Event is non-blocking and wakes readers waiting between
        polls.  A pipe is closed only after its reader's ``done`` Event proves
        that no read can be in progress.  A later call (or ``join_readers``)
        closes pipes whose readers completed after this call began.
        """
        self._stop.set()
        self._close_finished_streams()

    def _close_finished_streams(self) -> None:
        for stream, capture in (
            (self._stdout_stream, self._stdout),
            (self._stderr_stream, self._stderr),
        ):
            if capture.done.is_set():
                _close_pipe(stream)

    def text(self) -> tuple[str, str]:
        return self._stdout.text(), self._stderr.text()

    def stats(self) -> tuple[CaptureStats, CaptureStats]:
        return self._stdout.stats(), self._stderr.stats()
