"""Private permission primitives for trusted ToolHub state objects."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

TRUSTED_DIRECTORY_MODE = 0o700
TRUSTED_FILE_MODE = 0o600

_IS_POSIX = os.name == "posix"


def secure_trusted_directory(path: Path) -> None:
    """Guarantee that one ToolHub-owned state directory is exactly ``0700``.

    Linux ``O_PATH`` permits opening a directory created as ``0000`` by a
    restrictive umask; ``/proc/self/fd`` then provides an exact descriptor
    reference for chmod because Linux rejects ``fchmod`` on ``O_PATH``
    descriptors.  Other POSIX platforms use a normal directory descriptor,
    with a no-follow path chmod only when the local runtime explicitly
    supports it and restrictive permissions prevent the initial open.
    """
    if not _IS_POSIX:
        return

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise OSError(
            errno.ENOTSUP,
            "secure directory descriptors are unavailable on this POSIX platform",
            os.fspath(path),
        )

    path_flag = getattr(os, "O_PATH", 0)
    open_flags = directory_flag | nofollow_flag | (path_flag or os.O_RDONLY)
    try:
        descriptor = os.open(path, open_flags)
    except PermissionError:
        if os.chmod not in os.supports_follow_symlinks:
            raise
        os.chmod(path, TRUSTED_DIRECTORY_MODE, follow_symlinks=False)
        descriptor = os.open(path, directory_flag | nofollow_flag | os.O_RDONLY)

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise NotADirectoryError(
                errno.ENOTDIR,
                "trusted state root is not a directory",
                os.fspath(path),
            )

        try:
            os.fchmod(descriptor, TRUSTED_DIRECTORY_MODE)
        except OSError as exc:
            if not path_flag or exc.errno != errno.EBADF:
                raise
            # Linux exposes an O_PATH descriptor as a stable kernel-owned
            # symlink. Chmodding through it operates on the already-opened
            # directory even if the original pathname is concurrently changed.
            os.chmod(Path("/proc/self/fd") / str(descriptor), TRUSTED_DIRECTORY_MODE)

        after = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or stat.S_IMODE(after.st_mode) != TRUSTED_DIRECTORY_MODE
        ):
            raise OSError(
                errno.EPERM,
                "trusted state root permissions could not be secured",
                os.fspath(path),
            )
    finally:
        os.close(descriptor)


def secure_trusted_file_descriptor(descriptor: int) -> None:
    """Guarantee that an opened trusted regular file is exactly ``0600``."""
    if not _IS_POSIX:
        return

    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "trusted state object is not a regular file")

    os.fchmod(descriptor, TRUSTED_FILE_MODE)

    after = os.fstat(descriptor)
    if (
        not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or stat.S_IMODE(after.st_mode) != TRUSTED_FILE_MODE
    ):
        raise OSError(
            errno.EPERM,
            "trusted state file permissions could not be secured",
        )


def open_trusted_file(path: Path, flags: int, mode: int = TRUSTED_FILE_MODE) -> int:
    """Open and secure one trusted file, rejecting final-component symlinks.

    ``O_NOFOLLOW`` is used on POSIX where available.  The fallback identity
    check happens before ``fchmod`` so a symlink target is never chmodded merely
    because its path was supplied as a trusted-state object.
    """
    if not _IS_POSIX:
        return os.open(path, flags, mode)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    before = None
    if not nofollow:
        try:
            before = path.lstat()
        except FileNotFoundError:
            pass

    descriptor = os.open(path, flags | nofollow, mode)
    try:
        if not nofollow:
            opened = os.fstat(descriptor)
            current = path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or (
                    before is not None
                    and (before.st_dev, before.st_ino)
                    != (current.st_dev, current.st_ino)
                )
            ):
                raise OSError(
                    errno.ELOOP,
                    "trusted state path was replaced or is not a regular file",
                    os.fspath(path),
                )
        secure_trusted_file_descriptor(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise

    return descriptor
