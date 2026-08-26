"""Resolve and fingerprint executables for immutable approval snapshots."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_WINDOWS = os.name == "nt"
_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class ExecutableSnapshot:
    """Canonical primary executable identity approved by a human."""

    path: Path
    sha256: str
    size: int

    def to_payload(self) -> dict[str, object]:
        return {
            "canonical_path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
        }


def _path_key(path: Path) -> tuple[int, int, int, int]:
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def fingerprint_executable(path: Path) -> ExecutableSnapshot:
    """Hash a canonical executable, rejecting files that change while read."""
    try:
        canonical = path.resolve(strict=True)
        initial_key = _path_key(canonical)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Approved executable no longer resolves safely.") from exc

    if initial_key[2] > _MAX_EXECUTABLE_BYTES:
        raise ValueError("Executable is too large to fingerprint safely.")

    digest = hashlib.sha256()
    try:
        with canonical.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("Executable is not a regular file.")
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ) != initial_key:
                raise ValueError("Executable changed before fingerprinting.")

            remaining = initial_key[2]
            while remaining:
                chunk = handle.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("Executable changed while it was fingerprinted.")
                digest.update(chunk)
                remaining -= len(chunk)
            if handle.read(1):
                raise ValueError("Executable changed while it was fingerprinted.")

            final_opened = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError("Executable could not be fingerprinted safely.") from exc

    final_key = (
        final_opened.st_dev,
        final_opened.st_ino,
        final_opened.st_size,
        final_opened.st_mtime_ns,
    )
    try:
        path_key_after_close = _path_key(canonical)
    except OSError as exc:
        raise ValueError("Executable changed while it was fingerprinted.") from exc
    if final_key != initial_key or path_key_after_close != initial_key:
        raise ValueError("Executable changed while it was fingerprinted.")

    return ExecutableSnapshot(canonical, digest.hexdigest(), initial_key[2])


def _windows_extensions(environment: Mapping[str, str]) -> tuple[str, ...]:
    values = environment.get("PATHEXT", _DEFAULT_PATHEXT).split(os.pathsep)
    extensions: list[str] = []
    for value in values:
        extension = value.strip()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = f".{extension}"
        if "/" in extension or "\\" in extension:
            continue
        extensions.append(extension)
    return tuple(extensions)


def _candidate_names(
    program: str,
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    if not _WINDOWS or Path(program).suffix:
        return (program,)
    return tuple(f"{program}{extension}" for extension in _windows_extensions(environment))


def _search_directories(
    working_directory: Path,
    environment: Mapping[str, str],
) -> tuple[Path, ...]:
    directories: list[Path] = [working_directory] if _WINDOWS else []
    for entry in environment.get("PATH", "").split(os.pathsep):
        if _WINDOWS and len(entry) >= 2 and entry[0] == entry[-1] == '"':
            entry = entry[1:-1]
        candidate = Path(entry) if entry else working_directory
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        directories.append(candidate)
    return tuple(directories)


def resolve_executable_snapshot(
    program: str,
    *,
    working_directory: Path,
    environment: Mapping[str, str] | None = None,
) -> ExecutableSnapshot:
    """Resolve approval-time executable selection and fingerprint it."""
    if not program or "\0" in program:
        raise ValueError("Executable name is empty or invalid.")

    env = environment if environment is not None else os.environ
    explicit = "/" in program or "\\" in program or Path(program).is_absolute()

    if explicit:
        candidate = Path(program)
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        candidates = (
            candidate.with_name(name)
            for name in _candidate_names(candidate.name, env)
        )
    else:
        candidates = (
            directory / name
            for directory in _search_directories(working_directory, env)
            for name in _candidate_names(program, env)
        )

    for candidate in candidates:
        try:
            canonical = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not canonical.is_file():
            continue
        if not _WINDOWS and not os.access(canonical, os.X_OK):
            continue
        return fingerprint_executable(canonical)

    raise ValueError(
        f"Executable could not be resolved at approval creation: {program}"
    )


def validate_executable_snapshot(payload: object) -> Path:
    """Re-hash a stored snapshot and return its unchanged canonical path."""
    if not isinstance(payload, dict):
        raise TypeError("Approval request has no executable snapshot.")

    raw_path = payload.get("canonical_path")
    expected_hash = payload.get("sha256")
    expected_size = payload.get("size")
    if (
        not isinstance(raw_path, str)
        or not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size < 0
    ):
        raise ValueError("Approval executable snapshot is malformed.")

    stored_path = Path(raw_path)
    if not stored_path.is_absolute():
        raise ValueError("Approval executable path is not absolute.")

    actual = fingerprint_executable(stored_path)
    if actual.path != stored_path:
        raise ValueError("Approval executable canonical path changed.")
    if actual.size != expected_size or not hmac.compare_digest(
        actual.sha256,
        expected_hash,
    ):
        raise ValueError("Approved executable content changed.")
    return actual.path
