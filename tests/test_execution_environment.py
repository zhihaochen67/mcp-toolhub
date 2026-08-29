"""Focused tests for minimal child-process environment snapshots."""

from __future__ import annotations

import copy

import pytest

from mcp_toolhub.security.execution_environment import (
    MAX_ENVIRONMENT_VARIABLES,
    build_execution_environment,
    is_forbidden_environment_name,
    parse_execution_environment_snapshot,
)


def test_posix_policy_inherits_no_parent_variables():
    parent = {
        "PATH": "/attacker/bin",
        "HOME": "/private/home",
        "TMPDIR": "/private/tmp",
        "LANG": "en_US.UTF-8",
        "TOOLHUB_TEST_SECRET_TOKEN": "secret",
        "PYTHONPATH": "/injected/python",
        "LD_PRELOAD": "/injected/loader.so",
        "NODE_OPTIONS": "--require=/injected/node.js",
    }

    snapshot = build_execution_environment(parent, windows=False)

    assert snapshot.platform == "posix"
    assert snapshot.environment() == {}
    assert snapshot.audit_metadata()["variable_count"] == 0


def test_windows_policy_preserves_only_valid_system_paths():
    parent = {
        "SYSTEMROOT": r"C:\Windows",
        "windir": r"C:\Windows",
        "TEMP": r"C:\Users\operator\AppData\Local\Temp",
        "TMP": r"C:\Temp",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "USERPROFILE": r"C:\Users\operator",
        "LOCALAPPDATA": r"C:\Users\operator\AppData\Local",
        "PATH": r"C:\attacker-bin",
        "PATHEXT": ".EXE;.CMD",
        "API_KEY": "secret",
    }

    snapshot = build_execution_environment(parent, windows=True)

    assert snapshot.platform == "windows"
    assert snapshot.environment() == {
        "SystemRoot": r"C:\Windows",
        "TEMP": r"C:\Users\operator\AppData\Local\Temp",
        "TMP": r"C:\Temp",
        "WINDIR": r"C:\Windows",
    }
    assert "PATH" not in snapshot.environment()
    assert "PATHEXT" not in snapshot.environment()


def test_invalid_windows_system_paths_are_omitted():
    snapshot = build_execution_environment(
        {
            "SystemRoot": "relative-system-root",
            "WINDIR": "%SystemRoot%",
            "TEMP": "relative-temp",
            "TMP": "",
        },
        windows=True,
    )

    assert snapshot.environment() == {}


def test_snapshot_is_deterministic_across_parent_order():
    first = build_execution_environment(
        {"TEMP": r"C:\Temp", "SystemRoot": r"C:\Windows"},
        windows=True,
    )
    second = build_execution_environment(
        {"SystemRoot": r"C:\Windows", "TEMP": r"C:\Temp"},
        windows=True,
    )

    assert first == second
    assert first.to_payload() == second.to_payload()


def test_valid_snapshot_round_trips():
    built = build_execution_environment(
        {"SystemRoot": r"C:\Windows", "TEMP": r"C:\Temp"},
        windows=True,
    )

    parsed = parse_execution_environment_snapshot(
        built.to_payload(),
        windows=True,
    )

    assert parsed == built


def test_snapshot_digest_detects_value_tampering():
    snapshot = build_execution_environment(
        {"SystemRoot": r"C:\Windows"},
        windows=True,
    ).to_payload()
    snapshot["variables"]["SystemRoot"] = r"C:\Other"

    with pytest.raises(ValueError, match="digest"):
        parse_execution_environment_snapshot(snapshot, windows=True)


@pytest.mark.parametrize(
    "name",
    [
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PYTHONWARNINGS",
        "PYTHONUSERBASE",
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
        "PSModulePath",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SERVICE_AUTH",
        "PRIVATE_KEY_FILE",
        "session_cookie",
    ],
)
def test_injection_and_secret_names_are_explicitly_forbidden(name):
    assert is_forbidden_environment_name(name) is True


def test_code_owned_safe_git_controls_can_be_added():
    snapshot = build_execution_environment(
        {},
        additional_variables={
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
        },
        windows=False,
    )

    assert snapshot.environment() == {
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    }


def test_forbidden_code_owned_addition_is_rejected():
    with pytest.raises(ValueError, match="forbidden"):
        build_execution_environment(
            {},
            additional_variables={"PYTHONPATH": "/injected"},
            windows=False,
        )


@pytest.mark.parametrize(
    "variables",
    [
        {"SystemRoot\0": r"C:\Windows"},
        {"SystemRoot": "bad\0value"},
        {"SystemRoot": 123},
        {"SystemRoot": r"C:\Windows", "SYSTEMROOT": r"C:\Other"},
        {f"X{index}": "value" for index in range(MAX_ENVIRONMENT_VARIABLES + 1)},
    ],
    ids=["nul-key", "nul-value", "non-string", "case-duplicate", "too-many"],
)
def test_malformed_windows_snapshot_variables_fail_closed(variables):
    payload = {
        "policy_version": 1,
        "platform": "windows",
        "variables": variables,
        "sha256": "0" * 64,
    }

    with pytest.raises((TypeError, ValueError)):
        parse_execution_environment_snapshot(payload, windows=True)


def test_windows_parent_duplicate_names_are_rejected_case_insensitively():
    with pytest.raises(ValueError, match="duplicate"):
        build_execution_environment(
            {"Path": r"C:\one", "PATH": r"C:\two"},
            windows=True,
        )


def test_snapshot_schema_and_platform_are_strict():
    snapshot = build_execution_environment({}, windows=False).to_payload()
    with_extra = copy.deepcopy(snapshot)
    with_extra["unexpected"] = True

    with pytest.raises(ValueError, match="malformed"):
        parse_execution_environment_snapshot(with_extra, windows=False)
    with pytest.raises(ValueError, match="malformed"):
        parse_execution_environment_snapshot(snapshot, windows=True)
