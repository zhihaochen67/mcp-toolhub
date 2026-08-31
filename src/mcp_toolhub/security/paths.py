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

if os.name == "nt":
    import msvcrt
else:
    import fcntl

MAX_FILE_SIZE = 256 * 1024  # 256 KB

_BINDING_FILENAME = "workspace-binding.json"
_BINDING_SCHEMA_VERSION = 1
_BINDING_READ_TIMEOUT_SECONDS = 0.5
_BINDING_READ_INTERVAL_SECONDS = 0.01
_BINDING_LOCK_TIMEOUT_SECONDS = 5.0
_BINDING_LOCK_RETRY_SECONDS = 0.05


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
            payload = json.loads(binding_path.read_text(encoding="utf-8"))
        except StateConfigurationError:
            raise
        except (json.JSONDecodeError, OSError, UnicodeError) as exc:
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
    descriptor = os.open(lock_path, open_flags, 0o600)
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


def _publish_binding_manifest(binding_path: Path, serialized: bytes) -> None:
    """Atomically publish a complete manifest without replacing any binding."""
    temporary_path = binding_path.with_name(
        f".{binding_path.name}-{secrets.token_hex(8)}.tmp"
    )
    open_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None

    try:
        descriptor = os.open(temporary_path, open_flags, 0o600)
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
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    else:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass


def _bind_state_namespace(state_root: Path, workspace_root: Path) -> None:
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

    try:
        unresolved_state_root = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            f"Invalid TOOLHUB_STATE_ROOT: path cannot be resolved: {candidate}"
        ) from exc

    if _state_is_inside_workspace(unresolved_state_root, workspace_root):
        raise RuntimeConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )

    try:
        candidate.mkdir(parents=True, exist_ok=True)
        state_root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StateConfigurationError(
            "Invalid TOOLHUB_STATE_ROOT: path cannot be created or resolved: "
            f"{candidate}"
        ) from exc

    if not state_root.is_dir():
        raise StateConfigurationError(
            f"Invalid TOOLHUB_STATE_ROOT: path is not a directory: {state_root}"
        )

    _bind_state_namespace(state_root, workspace_root)

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
        state_root = configuration.state_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeConfigurationError(
            "Supplied runtime configuration contains an unavailable root"
        ) from exc

    if not workspace_root.is_dir() or not state_root.is_dir():
        raise RuntimeConfigurationError(
            "Supplied runtime configuration roots must be directories"
        )
    if (
        workspace_root != configuration.workspace_root
        or state_root != configuration.state_root
    ):
        raise RuntimeConfigurationError(
            "Supplied runtime configuration roots must be canonical"
        )
    if _state_is_inside_workspace(state_root, workspace_root):
        raise RuntimeConfigurationError(
            "Invalid runtime configuration: TOOLHUB_STATE_ROOT must be outside "
            "TOOLHUB_WORKSPACE_ROOT"
        )


def initialize_runtime_configuration(
    configuration: RuntimeConfiguration | None = None,
) -> RuntimeConfiguration:
    """Install or load the immutable process-level runtime configuration.

    Importing modules does not capture environment state. The server and
    administrator entry points call this explicitly, while direct library use
    initializes lazily on first access.
    """

    global _configuration

    if configuration is not None:
        _validate_supplied_configuration(configuration)

    if _configuration is None:
        with _configuration_lock:
            if _configuration is None:
                _configuration = configuration or _load_runtime_configuration()

    if configuration is not None and configuration != _configuration:
        raise RuntimeConfigurationError(
            "Runtime configuration is already frozen for this process"
        )

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

    if is_portably_rooted_path(path):
        raise ValueError(f"Access denied: path escapes workspace: {path}")

    effective_root = (root or get_workspace_root()).resolve()
    target = (effective_root / path).resolve()

    try:
        target.relative_to(effective_root)
    except ValueError as exc:
        raise ValueError(f"Access denied: path escapes workspace: {path}") from exc

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
