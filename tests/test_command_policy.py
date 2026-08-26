"""Focused tests for executable provenance and exact LOW profiles."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from mcp_toolhub.security.command_policy import assess_shell_command
from mcp_toolhub.security.risk import RiskLevel


def _executable_name(stem: str) -> str:
    return f"{stem}.exe" if os.name == "nt" else stem


def _make_executable(directory: Path, stem: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _executable_name(stem)
    path.write_text("attacker-controlled executable", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path.resolve()


def _assess(
    program: str,
    args: list[str],
    *,
    workspace: Path,
    environment: dict[str, str] | None = None,
):
    return assess_shell_command(
        program,
        args,
        working_directory=workspace,
        workspace_root=workspace,
        environment=environment,
    )


def test_external_user_writable_path_cannot_supply_low_executable(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    attacker_bin = (temp_dir / "Downloads" / "bin").resolve()
    workspace.mkdir()
    attacker_python = _make_executable(attacker_bin, "python")
    environment = {
        "PATH": os.pathsep.join(("", ".", str(workspace), str(attacker_bin))),
        "PATHEXT": ".CMD;.EXE",
    }

    decision = _assess(
        "python",
        ["--version"],
        workspace=workspace,
        environment=environment,
    )

    assert decision.level == RiskLevel.LOW
    assert decision.executable.lookup == "toolhub_runtime"
    assert decision.executable.resolved_path == Path(sys.executable).resolve()
    assert decision.executable.resolved_path != attacker_python
    assert decision.intrinsic_stdout is not None


def test_arbitrary_absolute_python_is_not_trusted(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    attacker_bin = (temp_dir / "tools").resolve()
    workspace.mkdir()
    attacker_python = _make_executable(attacker_bin, "python")

    decision = _assess(
        str(attacker_python),
        ["--version"],
        workspace=workspace,
        environment={"PATH": str(attacker_bin)},
    )

    assert decision.level == RiskLevel.MEDIUM
    assert decision.executable.lookup == "explicit_path"
    assert decision.executable.resolved_path == attacker_python
    assert decision.executable.trusted is False
    assert decision.profile is None


@pytest.mark.parametrize(
    ("stem", "expected"),
    [("python", RiskLevel.MEDIUM), ("git", RiskLevel.HIGH)],
)
def test_workspace_executable_spoofs_are_never_low(temp_dir, stem, expected):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()
    spoof = _make_executable(workspace, stem)

    decision = _assess(str(spoof), ["--version"], workspace=workspace)

    assert decision.level == expected
    assert decision.level != RiskLevel.LOW
    assert decision.executable.resolved_path == spoof
    assert decision.executable.trusted is False


def test_exact_absolute_toolhub_runtime_path_is_low(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess(
        sys.executable,
        ["-V"],
        workspace=workspace,
        environment={"PATH": ""},
    )

    assert decision.level == RiskLevel.LOW
    assert decision.profile == "python.version.short"
    assert decision.executable.resolved_path == Path(sys.executable).resolve()
    assert decision.executable.trusted is True


def test_relative_executable_path_is_never_low(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()
    spoof = _make_executable(workspace, "python")
    relative_program = f".{os.sep}{spoof.name}"

    decision = _assess(
        relative_program,
        ["--version"],
        workspace=workspace,
    )

    assert decision.level == RiskLevel.MEDIUM
    assert decision.executable.lookup == "explicit_path"
    assert decision.executable.resolved_path == spoof
    assert decision.executable.trusted is False


@pytest.mark.parametrize("launcher", ["py", "py.exe"])
def test_windows_python_launcher_is_always_high(temp_dir, launcher):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess(launcher, ["--version"], workspace=workspace)

    assert decision.level == RiskLevel.HIGH
    assert decision.profile is None
    assert decision.executable.trusted is False
    assert "selects another Python interpreter" in decision.reason


@pytest.mark.parametrize("script", ["build.cmd", "build.bat"])
def test_windows_batch_scripts_are_high(temp_dir, script):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess(script, ["safe-looking"], workspace=workspace)

    assert decision.level == RiskLevel.HIGH
    assert "command interpreter" in decision.reason


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--version"], RiskLevel.LOW),
        (["-V"], RiskLevel.LOW),
        (["-v"], RiskLevel.MEDIUM),
        (["--version", "extra"], RiskLevel.MEDIUM),
        (["-c", "print('x')"], RiskLevel.HIGH),
    ],
)
def test_python_low_profiles_are_exact(temp_dir, args, expected):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess("python", args, workspace=workspace)

    assert decision.level == expected


def test_unavailable_runtime_fails_closed_to_medium(temp_dir, monkeypatch):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()
    monkeypatch.setattr(
        "mcp_toolhub.security.command_policy.sys.executable",
        str(temp_dir / "missing-python"),
    )

    decision = _assess(
        "python",
        ["--version"],
        workspace=workspace,
    )

    assert decision.level == RiskLevel.MEDIUM
    assert decision.profile is None
    assert decision.executable.trusted is False


def test_pathext_script_is_not_a_python_low_alias(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    attacker_bin = (temp_dir / "tools").resolve()
    workspace.mkdir()
    attacker_bin.mkdir()
    script = attacker_bin / "python.cmd"
    script.write_text("@echo malicious", encoding="utf-8")

    decision = _assess(
        "python.cmd",
        ["--version"],
        workspace=workspace,
        environment={"PATH": str(attacker_bin), "PATHEXT": ".CMD;.EXE"},
    )

    assert decision.level == RiskLevel.HIGH
    assert decision.profile is None


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["status"],
        ["diff"],
        ["push"],
        ["--no-pager", "status"],
        ["diff", "--ext-diff"],
        ["diff", "--textconv"],
        ["--help"],
        ["status", "--help"],
        ["-c", "core.pager=cat", "status"],
        ["--config=core.pager=cat", "status"],
        ["--git-dir", "repo", "status"],
        ["status", "--work-tree=repo"],
        ["made-up-helper"],
    ],
)
def test_generic_git_is_always_high_and_never_low(temp_dir, args):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess("git", args, workspace=workspace)

    assert decision.level == RiskLevel.HIGH
    assert decision.profile is None
    assert decision.executable.trusted is False


def test_pytest_remains_approval_gated(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess("pytest", ["--version"], workspace=workspace)

    assert decision.level == RiskLevel.MEDIUM
    assert decision.profile is None


def test_unknown_executable_is_high(temp_dir):
    workspace = (temp_dir / "workspace").resolve()
    workspace.mkdir()

    decision = _assess("mystery", ["--version"], workspace=workspace)

    assert decision.level == RiskLevel.HIGH
    assert decision.profile is None
