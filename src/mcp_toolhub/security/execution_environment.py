"""Minimal, versioned environments for ToolHub child processes.

Approved shell commands receive only the environment captured in their
protected approval snapshot.  The allowlist is intentionally small because
the approved primary executable is launched by absolute path and ToolHub
decodes process output explicitly as UTF-8.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PureWindowsPath

EXECUTION_ENVIRONMENT_POLICY_VERSION = 1
MAX_ENVIRONMENT_VARIABLES = 16
MAX_ENVIRONMENT_KEY_CHARS = 128
MAX_ENVIRONMENT_VALUE_CHARS = 4096

_PLATFORM_WINDOWS = "windows"
_PLATFORM_POSIX = "posix"

# These are the only parent-process values inherited by approved shell
# commands.  POSIX intentionally has no inherited baseline: absolute primary
# executable launch and explicit UTF-8 decoding do not require PATH or locale.
_WINDOWS_INHERITED_VARIABLES = {
    "systemroot": "SystemRoot",
    "windir": "WINDIR",
    "temp": "TEMP",
    "tmp": "TMP",
}

_FORBIDDEN_NAMES = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PYTHONWARNINGS",
        "PYTHONUSERBASE",
        # ToolHub neither inherits nor injects this Python behavior toggle.
        "PYTHONSAFEPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "BASH_ENV",
        "ENV",
        "CDPATH",
        "IFS",
        "PATHEXT",
        "PATH",
        "PROMPT",
        "PSMODULEPATH",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
    }
)
_FORBIDDEN_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
_SECRET_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|APIKEY|AUTH|CREDENTIAL|COOKIE|PRIVATE[_-]?KEY",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExecutionEnvironmentSnapshot:
    """Canonical child environment and its approval-bound identity."""

    policy_version: int
    platform: str
    variables: tuple[tuple[str, str], ...]
    sha256: str

    def environment(self) -> dict[str, str]:
        return dict(self.variables)

    def to_payload(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "platform": self.platform,
            "variables": self.environment(),
            "sha256": self.sha256,
        }

    def audit_metadata(self) -> dict[str, object]:
        """Return bounded metadata only; never return keys or values."""
        return {
            "policy_version": self.policy_version,
            "variable_count": len(self.variables),
            "sha256": self.sha256,
        }


def _platform(*, windows: bool | None) -> str:
    is_windows = os.name == "nt" if windows is None else windows
    return _PLATFORM_WINDOWS if is_windows else _PLATFORM_POSIX


def _name_key(name: str, *, platform: str) -> str:
    return name.casefold() if platform == _PLATFORM_WINDOWS else name


def is_forbidden_environment_name(name: str) -> bool:
    """Apply explicit injection/secret deny rules case-insensitively."""
    normalized = name.upper()
    return (
        normalized in _FORBIDDEN_NAMES
        or normalized.startswith(_FORBIDDEN_PREFIXES)
        or _SECRET_NAME.search(name) is not None
    )


def _validate_entry(key: object, value: object) -> tuple[str, str]:
    if not isinstance(key, str) or not isinstance(value, str):
        raise TypeError("Execution environment keys and values must be strings.")
    if not key or len(key) > MAX_ENVIRONMENT_KEY_CHARS or "=" in key or "\0" in key:
        raise ValueError("Execution environment contains an invalid variable name.")
    if len(value) > MAX_ENVIRONMENT_VALUE_CHARS or "\0" in value:
        raise ValueError("Execution environment contains an invalid variable value.")
    return key, value


def _validated_items(
    variables: Mapping[object, object],
    *,
    platform: str,
) -> list[tuple[str, str]]:
    if len(variables) > MAX_ENVIRONMENT_VARIABLES:
        raise ValueError("Execution environment contains too many variables.")

    seen: set[str] = set()
    validated: list[tuple[str, str]] = []
    for raw_key, raw_value in variables.items():
        key, value = _validate_entry(raw_key, raw_value)
        normalized = _name_key(key, platform=platform)
        if normalized in seen:
            raise ValueError("Execution environment contains duplicate variable names.")
        seen.add(normalized)
        if is_forbidden_environment_name(key):
            raise ValueError("Execution environment contains a forbidden variable.")
        validated.append((key, value))
    return validated


def _canonical_items(
    items: list[tuple[str, str]],
    *,
    platform: str,
) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(items, key=lambda item: _name_key(item[0], platform=platform)))


def _digest(
    *,
    policy_version: int,
    platform: str,
    variables: tuple[tuple[str, str], ...],
) -> str:
    canonical = {
        "platform": platform,
        "policy_version": policy_version,
        "variables": [[key, value] for key, value in variables],
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _valid_windows_path(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and "\0" not in value
        and len(value) <= MAX_ENVIRONMENT_VALUE_CHARS
        and PureWindowsPath(value).is_absolute()
    )


def _parent_lookup(
    environment: Mapping[object, object],
    *,
    platform: str,
) -> dict[str, tuple[str, str]]:
    """Index a parent environment without copying any value into a child."""
    lookup: dict[str, tuple[str, str]] = {}
    for raw_key, raw_value in environment.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            raise TypeError("Parent environment keys and values must be strings.")
        normalized = _name_key(raw_key, platform=platform)
        if normalized in lookup:
            raise ValueError("Parent environment contains duplicate variable names.")
        lookup[normalized] = (raw_key, raw_value)
    return lookup


def build_execution_environment(
    environment: Mapping[object, object] | None = None,
    *,
    additional_variables: Mapping[object, object] | None = None,
    windows: bool | None = None,
) -> ExecutionEnvironmentSnapshot:
    """Build one minimal child environment from an allowlisted parent subset.

    ``additional_variables`` is for fixed, code-owned controls such as Git's
    read-only environment flags.  It is not exposed through any MCP input.
    """
    platform = _platform(windows=windows)
    source = os.environ if environment is None else environment
    lookup = _parent_lookup(source, platform=platform)
    selected: dict[str, str] = {}

    if platform == _PLATFORM_WINDOWS:
        for normalized, canonical_name in _WINDOWS_INHERITED_VARIABLES.items():
            parent = lookup.get(normalized)
            if parent is None:
                continue
            _raw_name, value = parent
            if _valid_windows_path(value):
                selected[canonical_name] = value

    if additional_variables is not None:
        for key, value in _validated_items(additional_variables, platform=platform):
            normalized = _name_key(key, platform=platform)
            if any(
                _name_key(existing, platform=platform) == normalized
                for existing in selected
            ):
                raise ValueError(
                    "Execution environment contains duplicate variable names."
                )
            selected[key] = value

    items = _validated_items(selected, platform=platform)
    canonical = _canonical_items(items, platform=platform)
    digest = _digest(
        policy_version=EXECUTION_ENVIRONMENT_POLICY_VERSION,
        platform=platform,
        variables=canonical,
    )
    return ExecutionEnvironmentSnapshot(
        EXECUTION_ENVIRONMENT_POLICY_VERSION,
        platform,
        canonical,
        digest,
    )


def parse_execution_environment_snapshot(
    payload: object,
    *,
    windows: bool | None = None,
) -> ExecutionEnvironmentSnapshot:
    """Validate an approved-shell environment snapshot and its digest."""
    if not isinstance(payload, dict):
        raise TypeError("Approval request has no execution environment snapshot.")
    if set(payload) != {"policy_version", "platform", "variables", "sha256"}:
        raise ValueError("Approval execution environment snapshot is malformed.")

    policy_version = payload.get("policy_version")
    expected_platform = _platform(windows=windows)
    stored_platform = payload.get("platform")
    raw_variables = payload.get("variables")
    expected_digest = payload.get("sha256")
    if (
        not isinstance(policy_version, int)
        or isinstance(policy_version, bool)
        or policy_version != EXECUTION_ENVIRONMENT_POLICY_VERSION
        or stored_platform != expected_platform
        or not isinstance(raw_variables, dict)
        or not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise ValueError("Approval execution environment snapshot is malformed.")

    items = _validated_items(raw_variables, platform=expected_platform)
    allowed = (
        set(_WINDOWS_INHERITED_VARIABLES.values())
        if expected_platform == _PLATFORM_WINDOWS
        else set()
    )
    for key, value in items:
        if key not in allowed:
            raise ValueError(
                "Approval execution environment contains a non-allowlisted variable."
            )
        if expected_platform == _PLATFORM_WINDOWS and not _valid_windows_path(value):
            raise ValueError(
                "Approval execution environment contains an invalid system path."
            )

    canonical = _canonical_items(items, platform=expected_platform)
    actual_digest = _digest(
        policy_version=policy_version,
        platform=expected_platform,
        variables=canonical,
    )
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError("Approval execution environment digest does not match.")

    return ExecutionEnvironmentSnapshot(
        policy_version,
        expected_platform,
        canonical,
        actual_digest,
    )
