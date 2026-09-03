"""Frozen runtime configuration and workspace containment helpers."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from platformdirs import user_state_path

from mcp_toolhub.security.state_permissions import (
    TRUSTED_FILE_MODE,
    open_trusted_file,
    secure_trusted_directory,
    secure_trusted_file_descriptor,
)

if os.name == "nt":
    import msvcrt
else:
    import fcntl

MAX_FILE_SIZE = 256 * 1024  # 256 KB

_BINDING_FILENAME = "workspace-binding.json"
_BINDING_SCHEMA_VERSION = 1
_BINDING_MAX_READ_BYTES = 256 * 1024
_BINDING_READ_TIMEOUT_SECONDS = 0.5
_BINDING_READ_INTERVAL_SECONDS = 0.01
_BINDING_LOCK_TIMEOUT_SECONDS = 5.0
_BINDING_LOCK_RETRY_SECONDS = 0.05

_STATE_REGULAR_FILENAMES = frozenset(
    {
        _BINDING_FILENAME,
        f"{_BINDING_FILENAME}.lock",
        "approvals.json",
        "approvals.json.lock",
        "audit.jsonl",
        "audit.jsonl.lock",
    }
)
_STATE_TEMPORARY_NAMES = (
    (f".{_BINDING_FILENAME}-", ".tmp"),
    (".approvals-", ".tmp"),
    (".audit-", ".tmp"),
)


class RuntimeConfigurationError(ValueError):
    """The trusted process-level runtime configuration is invalid."""


class WorkspaceConfigurationError(RuntimeConfigurationError):
    """The trusted process-level workspace configuration is invalid."""


class StateConfigurationError(RuntimeConfigurationError):
    """The trusted process-level state configuration is invalid."""


@dataclass(frozen=True)
class RuntimeConfiguration:
    """Canonical roots shared by every ToolHub surface for one process."""

    state_root: Path
    workspace_root: Path


_configuration: RuntimeConfiguration | None = None


def is_portably_rooted_path(path: str) -> bool:
    """Recognize rooted path syntax independently of the current host OS.

    Workspace/repository path parameters are relative API values, so reject
    POSIX roots, Windows roots/UNC paths, and Windows drive-relative forms
    such as ``C:foo`` before applying host-native canonical containment.
    """

    windows_path = PureWindowsPath(path)
    return PurePosixPath(path).is_absolute() or bool(
        windows_path.drive or windows_path.root
    )


def has_portable_parent_reference(path: str) -> bool:
    """Return whether ``path`` contains an explicit ``..`` component.

    Check both POSIX and Windows syntax regardless of the host. MCP path
    values are portable API inputs; accepting a backslash traversal on POSIX
    and later interpreting the same stored value on Windows would make the
    boundary platform-dependent.
    """

    return ".." in PurePosixPath(path).parts or ".." in PureWindowsPath(path).parts


def _validate_workspace_path_input(path: str) -> None:
    """Reject malformed, rooted, or traversal-bearing workspace API paths."""

    if not isinstance(path, str):
        raise TypeError("Workspace path must be a string")
    if "\0" in path:
        raise ValueError("Access denied: workspace path is malformed")
    if is_portably_rooted_path(path) or has_portable_parent_reference(path):
        raise ValueError("Access denied: path escapes workspace")

    if os.name == "nt":
        # Relative Win32 device names and alternate data streams do not obey
        # ordinary file containment semantics. Reject them before Path opens
        # anything. Rooted/drive syntax was handled above.
        reserved_names = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{index}" for index in range(1, 10)),
            *(f"LPT{index}" for index in range(1, 10)),
        }
        for part in PureWindowsPath(path).parts:
            normalized = part.rstrip(" .")
            stem = normalized.split(".", 1)[0].upper()
            if ":" in part or stem in reserved_names:
                raise ValueError("Access denied: workspace path is unsafe")


_configuration_lock = threading.Lock()


def _load_workspace_root(environment: Mapping[str, str]) -> Path:
    value = environment.get("TOOLHUB_WORKSPACE_ROOT")
    if value is None:
        raise WorkspaceConfigurationError("TOOLHUB_WORKSPACE_ROOT is required")
    if not value.strip():
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: value is empty"
        )

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: path must be absolute"
        )

    try:
        workspace_root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceConfigurationError(
            "Invalid TOOLHUB_WORKSPACE_ROOT: path does not exist or cannot "
            f"be resolved: {candidate}"
        ) from exc

    if not workspace_root.is_dir():
        raise WorkspaceConfigurationError(
            f"Invalid TOOLHUB_WORKSPACE_ROOT: path is not a directory: {workspace_root}"
        )

    return workspace_root


def _state_is_inside_workspace(state_root: Path, workspace_root: Path) -> bool:
    try:
        state_root.relative_to(workspace_root)
    except ValueError:
        return False
    return True


def _workspace_key(workspace_root: Path) -> str:
    """Return a stable canonical workspace identity for the local platform."""
    value = os.fspath(workspace_root)
    if os.name == "nt":
        value = os.path.normcase(value)
    return value


def _workspace_identifier(workspace_root: Path) -> str:
    """Return a filesystem-safe, non-secret namespace identifier."""
    identity = _workspace_key(workspace_root).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(identity).hexdigest()


def _binding_payload(workspace_root: Path) -> dict[str, object]:
    return {
        "schema_version": _BINDING_SCHEMA_VERSION,
        "canonical_workspace": str(workspace_root),
    }


def _validate_binding_payload(payload: object, workspace_root: Path) -> None:
    if not isinstance(payload, dict):
        raise StateConfigurationError(
            "Invalid workspace binding: manifest must contain a JSON object"
        )

    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != _BINDING_SCHEMA_VERSION
    ):
        raise StateConfigurationError(
            "Invalid workspace binding: unsupported or missing schema_version"
        )

    raw_workspace = payload.get("canonical_workspace")
    if not isinstance(raw_workspace, str) or not raw_workspace.strip():
        raise StateConfigurationError(
            "Invalid workspace binding: canonical_workspace is missing or malformed"
        )

    bound_path = Path(raw_workspace)
    if not bound_path.is_absolute():
        raise StateConfigurationError(
            "Invalid workspace binding: canonical_workspace is not absolute"
        )

    try:
        bound_workspace = bound_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid workspace binding: canonical_workspace cannot be resolved"
        ) from exc

    if not bound_workspace.is_dir():
        raise StateConfigurationError(
            "Invalid workspace binding: canonical_workspace is not a directory"
        )

    if _workspace_key(bound_workspace) != _workspace_key(workspace_root):
        raise StateConfigurationError(
            "Invalid workspace binding: state namespace belongs to a different "
            "ToolHub workspace"
        )


def _read_binding_manifest(binding_path: Path, workspace_root: Path) -> None:
    """Read a binding, tolerating only a concurrent initializer's short write."""
    deadline = time.monotonic() + _BINDING_READ_TIMEOUT_SECONDS

    while True:
        try:
            if binding_path.is_symlink():
                raise StateConfigurationError(
                    "Invalid workspace binding: manifest must not be a symlink"
                )
            info = binding_path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise StateConfigurationError(
                    "Invalid workspace binding: manifest is not a regular file"
                )
            open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            descriptor = open_trusted_file(binding_path, open_flags)
            with os.fdopen(descriptor, "rb") as handle:
                serialized = handle.read(_BINDING_MAX_READ_BYTES + 1)
            if len(serialized) > _BINDING_MAX_READ_BYTES:
                raise StateConfigurationError(
                    "Invalid workspace binding: manifest exceeds maximum size"
                )
            payload = json.loads(serialized.decode("utf-8"))
        except StateConfigurationError:
            raise
        except (json.JSONDecodeError, OSError, RecursionError, UnicodeError) as exc:
            if time.monotonic() < deadline:
                time.sleep(_BINDING_READ_INTERVAL_SECONDS)
                continue
            raise StateConfigurationError(
                "Invalid workspace binding: manifest is unreadable or malformed"
            ) from exc

        _validate_binding_payload(payload, workspace_root)
        return


def _acquire_binding_os_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_binding_os_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _is_binding_lock_contention(exc: OSError) -> bool:
    if os.name == "nt":
        winerror = getattr(exc, "winerror", None)
        if winerror is not None:
            return winerror in {33, 36}
    return exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


@contextmanager
def _binding_lock(
    binding_path: Path,
    *,
    timeout_seconds: float | None = None,
) -> Iterator[None]:
    """Hold the stable OS-backed lock for one binding decision."""
    lock_path = binding_path.with_name(binding_path.name + ".lock")
    timeout = (
        _BINDING_LOCK_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    )
    deadline = time.monotonic() + timeout
    open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = open_trusted_file(lock_path, open_flags)
    locked = False

    try:
        while True:
            try:
                _acquire_binding_os_lock(descriptor)
                locked = True
                break
            except OSError as exc:
                if not _is_binding_lock_contention(exc):
                    raise

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Workspace binding lock acquisition timed out."
                    ) from exc
                time.sleep(min(_BINDING_LOCK_RETRY_SECONDS, remaining))

        yield
    finally:
        if locked:
            try:
                _release_binding_os_lock(descriptor)
            except OSError:
                pass
        try:
            os.close(descriptor)
        except OSError:
            pass


def _create_binding_temporary_file(temporary_path: Path) -> int:
    """Exclusively create and secure one owned binding temporary file."""
    open_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary_path, open_flags, TRUSTED_FILE_MODE)

    try:
        # O_CREAT | O_EXCL makes creation fail for an existing final component,
        # including a symlink, without duplicating the trusted open helper's
        # O_NOFOLLOW compatibility logic.
        secure_trusted_file_descriptor(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return descriptor


def _publish_binding_manifest(binding_path: Path, serialized: bytes) -> None:
    """Atomically publish a complete manifest without replacing any binding."""
    temporary_path = binding_path.with_name(
        f".{binding_path.name}-{secrets.token_hex(8)}.tmp"
    )
    descriptor: int | None = None
    temporary_owned = False

    try:
        descriptor = _create_binding_temporary_file(temporary_path)
        temporary_owned = True
        written = 0
        while written < len(serialized):
            count = os.write(descriptor, serialized[written:])
            if count <= 0:
                raise OSError("workspace binding write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        # A hard-link publication is atomic and fails if the destination exists.
        # Unlike os.replace (and POSIX os.rename), it can never become a rebind.
        try:
            os.link(temporary_path, binding_path)
        except FileExistsError:
            pass
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_owned:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    else:
        if temporary_owned:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _bind_state_namespace(
    state_root: Path,
    workspace_root: Path,
    *,
    inspect_state: bool = False,
) -> None:
    """Exclusively bind one trusted state namespace to one workspace."""
    binding_path = state_root / _BINDING_FILENAME
    serialized = (
        json.dumps(
            _binding_payload(workspace_root),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")

    try:
        with _binding_lock(binding_path):
            if inspect_state:
                _inspect_state_directory(state_root, workspace_root)
            try:
                binding_path.lstat()
            except FileNotFoundError:
                _publish_binding_manifest(binding_path, serialized)

            _read_binding_manifest(binding_path, workspace_root)
    except TimeoutError as exc:
        raise StateConfigurationError(
            "Invalid workspace binding: initialization lock acquisition timed out"
        ) from exc
    except OSError as exc:
        raise StateConfigurationError(
            "Invalid workspace binding: initialization failed"
        ) from exc


def _ensure_directory_component(
    parent: Path,
    name: str,
    *,
    secure_existing: bool,
    created_directories: list[Path] | None = None,
) -> Path:
    """Create and secure one component, optionally tightening an existing one."""
    if not name or Path(name).name != name:
        raise OSError(errno.EINVAL, "invalid ToolHub state directory component")

    path = parent / name
    creation_mode = 0o777 if os.name == "nt" else 0o700
    created = True
    try:
        os.mkdir(path, creation_mode)
    except FileExistsError:
        created = False

    if created and created_directories is not None:
        created_directories.append(path)

    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise OSError(
            errno.ELOOP,
            "ToolHub state directory must not be a symlink",
            os.fspath(path),
        )
    if not stat.S_ISDIR(before.st_mode):
        raise NotADirectoryError(
            errno.ENOTDIR,
            "ToolHub state path is not a directory",
            os.fspath(path),
        )

    if created or secure_existing:
        # POSIX securing reopens the exact final component with O_NOFOLLOW
        # before chmod. The lstat above provides a clear cross-platform type
        # error but is not used as chmod authority.
        secure_trusted_directory(path)

    after = path.lstat()
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise OSError(
            errno.EAGAIN,
            "ToolHub state directory changed during initialization",
            os.fspath(path),
        )
    return path


def _secure_toolhub_directory(
    parent: Path,
    name: str,
    *,
    created_directories: list[Path] | None = None,
) -> Path:
    """Create or validate one ToolHub-owned directory below ``parent``."""
    return _ensure_directory_component(
        parent,
        name,
        secure_existing=True,
        created_directories=created_directories,
    )


def _existing_external_state_parent(path: Path) -> Path:
    """Resolve an existing non-ToolHub parent without changing its mode."""
    try:
        parent = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OSError(
            errno.ENOENT,
            "trusted state parent does not exist or cannot be resolved",
            os.fspath(path),
        ) from exc
    if not parent.is_dir():
        raise NotADirectoryError(
            errno.ENOTDIR,
            "trusted state parent is not a directory",
            os.fspath(parent),
        )
    return parent


def _ensure_directory_chain(
    target: Path,
    *,
    created_directories: list[Path] | None = None,
) -> Path:
    """Securely create each missing component below the deepest existing parent."""
    missing_components: list[str] = []
    ancestor = target

    while True:
        try:
            ancestor.lstat()
        except FileNotFoundError:
            parent = ancestor.parent
            if parent == ancestor or not ancestor.name:
                raise OSError(
                    errno.ENOENT,
                    "trusted state path has no existing ancestor",
                    os.fspath(target),
                )
            missing_components.append(ancestor.name)
            ancestor = parent
            continue
        break

    current = _existing_external_state_parent(ancestor)
    for name in reversed(missing_components):
        current = _ensure_directory_component(
            current,
            name,
            secure_existing=False,
            created_directories=created_directories,
        )
    return current


def _is_state_temporary_name(name: str) -> bool:
    return any(
        name.startswith(prefix) and name.endswith(suffix) and len(name) > len(prefix)
        for prefix, suffix in _STATE_TEMPORARY_NAMES
    )


def _inspect_state_directory(state_root: Path, workspace_root: Path) -> None:
    """Validate an existing state namespace without adopting unknown objects."""
    deadline = time.monotonic() + _BINDING_READ_TIMEOUT_SECONDS

    while True:
        try:
            root_info = state_root.lstat()
            if stat.S_ISLNK(root_info.st_mode):
                raise OSError(
                    errno.ELOOP,
                    "trusted state root must not be a symlink",
                    os.fspath(state_root),
                )
            if not stat.S_ISDIR(root_info.st_mode):
                raise NotADirectoryError(
                    errno.ENOTDIR,
                    "trusted state root is not a directory",
                    os.fspath(state_root),
                )

            with os.scandir(state_root) as iterator:
                entries = {entry.name: entry for entry in iterator}
        except (OSError, RuntimeError) as exc:
            raise StateConfigurationError(
                "Invalid TOOLHUB_STATE_ROOT: existing state cannot be inspected safely"
            ) from exc

        known_names = {
            name
            for name in entries
            if name in _STATE_REGULAR_FILENAMES or _is_state_temporary_name(name)
        }
        transient_disappeared = False
        for name in sorted(known_names):
            entry = entries[name]
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError as exc:
                if not _is_state_temporary_name(name):
                    raise StateConfigurationError(
                        "Invalid TOOLHUB_STATE_ROOT: state object cannot be "
                        "inspected safely"
                    ) from exc
                if time.monotonic() >= deadline:
                    raise StateConfigurationError(
                        "Invalid TOOLHUB_STATE_ROOT: state changed repeatedly "
                        "during inspection"
                    ) from exc
                transient_disappeared = True
                break
            except OSError as exc:
                raise StateConfigurationError(
                    "Invalid TOOLHUB_STATE_ROOT: state object cannot be inspected safely"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise StateConfigurationError(
                    "Invalid TOOLHUB_STATE_ROOT: state object must not be a "
                    f"symlink: {name}"
                )
            if not stat.S_ISREG(info.st_mode):
                raise StateConfigurationError(
                    "Invalid TOOLHUB_STATE_ROOT: state object is not a regular "
                    f"file: {name}"
                )

        if transient_disappeared:
            remaining = max(0.0, deadline - time.monotonic())
            time.sleep(min(_BINDING_READ_INTERVAL_SECONDS, remaining))
            continue

        unexpected_names = sorted(set(entries) - known_names)
        if unexpected_names:
            raise StateConfigurationError(
                "Invalid TOOLHUB_STATE_ROOT: unexpected state object: "
                f"{unexpected_names[0]}"
            )

        if _BINDING_FILENAME not in entries:
            return

        _read_binding_manifest(state_root / _BINDING_FILENAME, workspace_root)
        return


def _inspect_existing_state_candidate(
    state_directory: Path,
    workspace_root: Path,
) -> Path | None:
    """Return a canonical safe existing state root, or ``None`` if absent."""
    try:
        info = state_directory.lstat()
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state path cannot be inspected safely"
        ) from exc

    if stat.S_ISLNK(info.st_mode):
        error = OSError(
            errno.ELOOP,
            "trusted state root must not be a symlink",
            os.fspath(state_directory),
        )
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state path must not be a symlink"
        ) from error
    if not stat.S_ISDIR(info.st_mode):
        error = NotADirectoryError(
            errno.ENOTDIR,
            "trusted state root is not a directory",
            os.fspath(state_directory),
        )
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state path is not a directory"
        ) from error

    try:
        state_root = state_directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: existing state cannot be resolved safely"
        ) from exc

    if _state_is_inside_workspace(state_root, workspace_root):
        raise StateConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )

    _inspect_state_directory(state_root, workspace_root)
    return state_root


def _validate_planned_state_location(
    candidate: Path,
    workspace_root: Path,
) -> None:
    """Reject an unsafe state location before creating any directories."""
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        pass
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state path cannot be inspected safely"
        ) from exc
    else:
        if stat.S_ISLNK(info.st_mode):
            error = OSError(
                errno.ELOOP,
                "trusted state root must not be a symlink",
                os.fspath(candidate),
            )
            raise StateConfigurationError(
                "Invalid TOOLHUB_STATE_ROOT: state path must not be a symlink"
            ) from error

    try:
        planned_state_root = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state path cannot be resolved safely"
        ) from exc

    if _state_is_inside_workspace(planned_state_root, workspace_root):
        raise StateConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )


def _rollback_created_directories(created_directories: list[Path]) -> None:
    """Best-effort rollback of empty directories owned by this attempt."""
    for path in reversed(created_directories):
        try:
            path.rmdir()
        except OSError:
            # Never remove pre-existing state or files published by another
            # initializer, and never replace the original failure.
            pass


def _load_state_root(
    environment: Mapping[str, str],
    workspace_root: Path,
) -> Path:
    value = environment.get("TOOLHUB_STATE_ROOT")

    if value is None:
        base = user_state_path("mcp-toolhub", appauthor=False)
        candidate = base / "workspaces" / _workspace_identifier(workspace_root)
    else:
        if not value.strip():
            raise StateConfigurationError("Invalid TOOLHUB_STATE_ROOT: value is empty")
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise StateConfigurationError(
                "Invalid TOOLHUB_STATE_ROOT: path must be absolute"
            )

    _validate_planned_state_location(candidate, workspace_root)

    created_directories: list[Path] = []
    try:
        if value is None:
            external_parent = _ensure_directory_chain(
                base.parent,
                created_directories=created_directories,
            )
            toolhub_root = _secure_toolhub_directory(
                external_parent,
                base.name,
                created_directories=created_directories,
            )
            workspaces_root = _secure_toolhub_directory(
                toolhub_root,
                "workspaces",
                created_directories=created_directories,
            )
            state_name = _workspace_identifier(workspace_root)
            _inspect_existing_state_candidate(
                workspaces_root / state_name,
                workspace_root,
            )
            state_directory = _secure_toolhub_directory(
                workspaces_root,
                state_name,
                created_directories=created_directories,
            )
        else:
            if not candidate.name:
                raise OSError(
                    errno.EINVAL,
                    "TOOLHUB_STATE_ROOT must name a ToolHub-owned directory",
                )
            _inspect_existing_state_candidate(candidate, workspace_root)
            external_parent = _ensure_directory_chain(
                candidate.parent,
                created_directories=created_directories,
            )
            state_directory = _secure_toolhub_directory(
                external_parent,
                candidate.name,
                created_directories=created_directories,
            )

        state_info = state_directory.lstat()
        if stat.S_ISLNK(state_info.st_mode) or not stat.S_ISDIR(state_info.st_mode):
            raise OSError(
                errno.EAGAIN,
                "trusted state root changed during initialization",
                os.fspath(state_directory),
            )
        state_root = state_directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _rollback_created_directories(created_directories)
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: path cannot be created, resolved, or "
            "secured: "
            f"{candidate}"
        ) from exc
    except StateConfigurationError:
        _rollback_created_directories(created_directories)
        raise

    if not state_root.is_dir():
        _rollback_created_directories(created_directories)
        raise StateConfigurationError(
            f"Invalid TOOLHUB_STATE_ROOT: path is not a directory: {state_root}"
        )

    if _state_is_inside_workspace(state_root, workspace_root):
        _rollback_created_directories(created_directories)
        raise StateConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )

    try:
        # Reinspect after all directory operations. This closes the lifecycle
        # gap between initial discovery and binding and rejects objects that
        # appeared during initialization.
        _inspect_state_directory(state_root, workspace_root)
        _bind_state_namespace(state_root, workspace_root, inspect_state=True)
    except StateConfigurationError:
        _rollback_created_directories(created_directories)
        raise
    except (OSError, RuntimeError) as exc:
        _rollback_created_directories(created_directories)
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: state initialization failed"
        ) from exc

    return state_root


def _load_runtime_configuration() -> RuntimeConfiguration:
    environment = os.environ
    workspace_root = _load_workspace_root(environment)
    state_root = _load_state_root(environment, workspace_root)

    # Approval and audit state must never become agent-addressable.
    if _state_is_inside_workspace(state_root, workspace_root):
        raise RuntimeConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )

    return RuntimeConfiguration(
        state_root=state_root,
        workspace_root=workspace_root,
    )


def _validate_supplied_configuration(configuration: RuntimeConfiguration) -> None:
    try:
        workspace_root = configuration.workspace_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeConfigurationError(
            "Supplied runtime configuration contains an unavailable workspace root"
        ) from exc

    if not workspace_root.is_dir():
        raise RuntimeConfigurationError(
            "Supplied runtime configuration workspace root must be a directory"
        )
    if workspace_root != configuration.workspace_root:
        raise RuntimeConfigurationError(
            "Supplied runtime configuration workspace root must be canonical"
        )

    state_root = _inspect_existing_state_candidate(
        configuration.state_root,
        workspace_root,
    )
    if state_root is None:
        error = FileNotFoundError(
            errno.ENOENT,
            "supplied trusted state root does not exist",
            os.fspath(configuration.state_root),
        )
        raise StateConfigurationError(
            "Supplied runtime configuration contains an unavailable state root"
        ) from error
    if state_root != configuration.state_root:
        raise StateConfigurationError(
            "Supplied runtime configuration state root must be canonical"
        )
    if _state_is_inside_workspace(state_root, workspace_root):
        raise StateConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )
    try:
        secure_trusted_directory(state_root)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Supplied runtime configuration state root could not be secured"
        ) from exc

    _inspect_state_directory(state_root, workspace_root)
    _bind_state_namespace(state_root, workspace_root, inspect_state=True)


def initialize_runtime_configuration(
    configuration: RuntimeConfiguration | None = None,
) -> RuntimeConfiguration:
    """Install or load the immutable process-level runtime configuration.

    Importing modules does not capture environment state. The server and
    administrator entry points call this explicitly, while direct library use
    initializes lazily on first access.
    """

    global _configuration

    with _configuration_lock:
        if _configuration is not None:
            if configuration is not None and configuration != _configuration:
                raise RuntimeConfigurationError(
                    "Runtime configuration is already frozen for this process"
                )
            return _configuration

        if configuration is not None:
            _validate_supplied_configuration(configuration)
            _configuration = configuration
        else:
            _configuration = _load_runtime_configuration()
        return _configuration


def get_workspace_root() -> Path:
    """Return the one canonical workspace boundary shared by all tools."""

    return initialize_runtime_configuration().workspace_root


def get_state_root() -> Path:
    """Return the trusted state root shared by the server and admin CLI."""

    return initialize_runtime_configuration().state_root


def _reset_runtime_configuration_for_tests() -> None:
    """Clear process configuration so a test can model a fresh process."""

    global _configuration
    with _configuration_lock:
        _configuration = None


def resolve_path_within(path: str, root: Path | None = None) -> Path:
    """Resolve a user path and guarantee that it stays inside ``root``.

    When no explicit internal/test root is supplied, use the immutable
    process-level ToolHub workspace.
    """

    _validate_workspace_path_input(path)

    try:
        effective_root = (root or get_workspace_root()).resolve()
        target = (effective_root / path).resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError("Workspace path could not be resolved safely") from exc

    try:
        target.relative_to(effective_root)
    except ValueError as exc:
        raise ValueError("Access denied: path escapes workspace") from exc

    return target


def resolve_workspace_path(path: str) -> Path:
    """Resolve a user path inside the configured process workspace."""

    return resolve_path_within(path, get_workspace_root())


def relative_workspace_path(path: Path) -> str:
    """Return a stable configured-workspace-relative path for MCP results."""

    relative = path.relative_to(get_workspace_root())

    if str(relative) == ".":
        return "."

    return relative.as_posix()


def validate_workspace_snapshot(
    payload: object,
    root: Path | None = None,
) -> Path:
    """Require an approval payload bound to one canonical workspace."""
    if not isinstance(payload, Mapping):
        raise TypeError("Approval payload is malformed")

    raw_snapshot = payload.get("workspace_root")
    if not isinstance(raw_snapshot, str) or not raw_snapshot.strip():
        raise ValueError("Approval workspace snapshot is missing or malformed")

    snapshot = Path(raw_snapshot)
    if not snapshot.is_absolute():
        raise ValueError("Approval workspace snapshot is not absolute")

    try:
        approved_root = snapshot.resolve(strict=True)
        current_root = (root or get_workspace_root()).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(
            "Approval workspace no longer exists or cannot be resolved"
        ) from exc

    if approved_root != current_root:
        raise ValueError("Approval was created for a different ToolHub workspace")

    return approved_root
