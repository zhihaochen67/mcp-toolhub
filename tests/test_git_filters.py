"""Real, isolated regressions for helpers reachable from read-only Git tools."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_toolhub.observability import audit
from mcp_toolhub.tools import git as git_tools


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True, timeout=20
    ).stdout


def _commit(repo: Path) -> None:
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--no-gpg-sign",
        "-qm",
        "fixture",
    )


@pytest.fixture
def filter_repo(git_repo, monkeypatch):
    """Isolate both setup Git and every production Git subprocess from user config."""
    global_config = git_repo / ".git" / "isolated-global-config"
    system_config = git_repo / ".git" / "isolated-system-config"
    global_config.write_text("", encoding="utf-8")
    system_config.write_text("", encoding="utf-8")
    controlled = {
        "GIT_CONFIG_GLOBAL": str(global_config),
        "GIT_CONFIG_SYSTEM": str(system_config),
    }
    for key, value in controlled.items():
        monkeypatch.setenv(key, value)
    original = git_tools.build_execution_environment

    def isolated_environment(*args, **kwargs):
        snapshot = original(*args, **kwargs)
        return SimpleNamespace(environment=lambda: snapshot.environment() | controlled)

    monkeypatch.setattr(git_tools, "build_execution_environment", isolated_environment)
    (git_repo / "tracked.txt").write_text("original\n", encoding="utf-8")
    (git_repo / ".gitattributes").write_text(
        "tracked.txt filter=guard\n", encoding="utf-8"
    )
    _git(git_repo, "add", "tracked.txt", ".gitattributes")
    # Equal byte lengths plus a changed timestamp force status to compare content;
    # a size-only change can be reported without invoking the clean filter.
    (git_repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    os.utime(git_repo / "tracked.txt", (1_600_000_000, 1_600_000_000))
    return git_repo


def _helper(repo: Path, operation: str) -> tuple[str, Path]:
    marker = repo / ".git" / "private-helper-marker"
    script = repo / ".git" / "helper with spaces.py"
    script.write_text(
        "import sys\nfrom pathlib import Path\n"
        "Path(sys.argv[1]).write_text('executed', encoding='utf-8')\n"
        "if sys.argv[2] == 'clean':\n"
        "    sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    command = " ".join(
        shlex.quote(value)
        for value in [
            Path(sys.executable).as_posix(),
            script.as_posix(),
            marker.as_posix(),
            operation,
        ]
    )
    return command, marker


def _transport_helper(repo: Path) -> tuple[str, Path]:
    """Create a fast failing SSH command using only shell built-ins.

    A missing promisor object makes Git probe and retry the configured SSH
    command several times. Avoiding a Python process for every attempt keeps
    the positive-control path deterministic on Windows while retaining the
    observable external-helper side effect.
    """
    marker = repo / ".git" / "private-helper-marker"
    command = f"printf executed > {shlex.quote(marker.as_posix())} && false"
    return command, marker


def _inspect(repo: Path, tool: str):
    return (
        git_tools.git_status(root=repo)
        if tool == "status"
        else git_tools.git_diff(root=repo)
    )


@pytest.mark.parametrize("tool", ["status", "diff"])
@pytest.mark.parametrize("operation", ["clean", "process"])
def test_live_filter_trigger_is_refused_before_helper_execution(
    filter_repo, tool, operation
):
    command, marker = _helper(filter_repo, operation)
    _git(filter_repo, "config", f"filter.guard.{operation}", command)
    argv = (
        ["status", "--porcelain=v1", "--branch"]
        if tool == "status"
        else ["diff", "--no-ext-diff", "--no-textconv"]
    )

    # Reproduce the old path with the same sanitized, contained invocation.
    # The process fixture deliberately exits after its side effect, rather than
    # implementing the long-running filter handshake. Its error is immaterial.
    baseline = git_tools._run_git(filter_repo, argv)
    assert marker.exists(), baseline.stderr
    assert marker.read_text(encoding="utf-8") == "executed"
    marker.unlink()

    with pytest.raises(
        git_tools.GitCommandError, match="executable clean/process filter"
    ) as error:
        _inspect(filter_repo, tool)
    assert not marker.exists()
    assert command not in str(error.value)
    assert str(filter_repo) not in str(error.value)
    event = audit.read_recent()[-1]
    assert event["tool"] == f"git.{tool}"
    assert event["executed"] is False
    assert event["error_type"] == "GitError"
    assert str(filter_repo) not in event["error"]
    assert "helper with spaces" not in event["error"]


@pytest.mark.parametrize(
    "scope", ["global", "system", "include", "conditional-include"]
)
@pytest.mark.parametrize("operation", ["clean", "process"])
def test_effective_inherited_filter_configuration_is_checked(
    filter_repo, scope, operation
):
    command, marker = _helper(filter_repo, operation)
    if scope in {"global", "system"}:
        config = filter_repo / ".git" / f"isolated-{scope}-config"
    else:
        config = filter_repo / ".git" / "included-config"
        include_key = (
            "include.path"
            if scope == "include"
            else f"includeIf.gitdir/i:{(filter_repo / '.git').as_posix()}.path"
        )
        _git(filter_repo, "config", include_key, str(config))
    _git(
        filter_repo,
        "config",
        "--file",
        str(config),
        f"filter.guard.{operation}",
        command,
    )
    for tool in ("status", "diff"):
        with pytest.raises(
            git_tools.GitCommandError, match="executable clean/process filter"
        ):
            _inspect(filter_repo, tool)
        assert not marker.exists()


@pytest.mark.parametrize(
    "attributes",
    [
        "*.other filter=guard\n",
        "tracked.txt -filter\n",
        "tracked.txt !filter\n",
        "untracked.dat filter=guard\n",
    ],
)
def test_configured_but_irrelevant_filter_does_not_block_inspection(
    filter_repo, attributes
):
    command, marker = _helper(filter_repo, "clean")
    _git(
        filter_repo,
        "config",
        "--file",
        str(filter_repo / ".git/isolated-global-config"),
        "filter.guard.clean",
        command,
    )
    (filter_repo / ".gitattributes").write_text(attributes, encoding="utf-8")
    (filter_repo / "untracked.dat").write_text("untracked", encoding="utf-8")
    status = git_tools.git_status(root=filter_repo)
    diff = git_tools.git_diff(path="tracked.txt", root=filter_repo)
    assert not status.clean
    assert "+modified" in diff.raw
    assert not marker.exists()


def test_repository_without_executable_filters_retains_results(filter_repo):
    assert not git_tools.git_status(root=filter_repo).clean
    assert "+modified" in git_tools.git_diff(root=filter_repo).raw
    assert "+original" in git_tools.git_diff(staged=True, root=filter_repo).raw


@pytest.mark.parametrize("override", ["clean", "process"])
def test_effective_empty_override_is_not_an_executable_filter(filter_repo, override):
    command, marker = _helper(filter_repo, "clean")
    _git(
        filter_repo,
        "config",
        "--file",
        str(filter_repo / ".git/isolated-global-config"),
        "filter.guard.clean",
        command,
    )
    _git(filter_repo, "config", f"filter.guard.{override}", "")
    assert not git_tools.git_status(root=filter_repo).clean
    assert "+modified" in git_tools.git_diff(root=filter_repo).raw
    assert not marker.exists()


@pytest.mark.parametrize(
    "source", ["macro", "nested", "info", "index-fallback", "global-attributes"]
)
def test_git_resolves_effective_attribute_sources(filter_repo, source):
    command, marker = _helper(filter_repo, "clean")
    _git(filter_repo, "config", "filter.guard.clean", command)
    attributes = filter_repo / ".gitattributes"
    if source == "macro":
        attributes.write_text(
            "[attr]protected filter=guard\ntracked.txt protected\n", encoding="utf-8"
        )
    elif source == "nested":
        nested = filter_repo / "nested"
        nested.mkdir()
        attributes.write_text("", encoding="utf-8")
        (nested / "file.txt").write_text("before", encoding="utf-8")
        _git(filter_repo, "add", "nested/file.txt")
        (nested / ".gitattributes").write_text("*.txt filter=guard\n", encoding="utf-8")
        (nested / "file.txt").write_text("after changed", encoding="utf-8")
    elif source == "info":
        attributes.write_text("tracked.txt -filter\n", encoding="utf-8")
        (filter_repo / ".git/info/attributes").write_text(
            "tracked.txt filter=guard\n", encoding="utf-8"
        )
    elif source == "index-fallback":
        attributes.unlink()
    else:
        attributes.write_text("", encoding="utf-8")
        global_attributes = filter_repo / ".git" / "global-attributes"
        global_attributes.write_text("tracked.txt filter=guard\n", encoding="utf-8")
        _git(filter_repo, "config", "core.attributesFile", str(global_attributes))
    with pytest.raises(
        git_tools.GitCommandError, match="executable clean/process filter"
    ):
        git_tools.git_diff(root=filter_repo)
    assert not marker.exists()


def test_new_attribute_selection_of_known_driver_fails_without_unfiltered_result(
    filter_repo, monkeypatch
):
    command, marker = _helper(filter_repo, "clean")
    _git(filter_repo, "config", "filter.guard.clean", command)
    attributes = filter_repo / ".gitattributes"
    attributes.write_text("tracked.txt -filter\n", encoding="utf-8")
    original = git_tools._filter_safety_options

    def change_after_inspection(root, **kwargs):
        options = original(root, **kwargs)
        attributes.write_text("tracked.txt filter=guard\n", encoding="utf-8")
        return options

    monkeypatch.setattr(git_tools, "_filter_safety_options", change_after_inspection)
    with pytest.raises(git_tools.GitCommandError, match="command failed"):
        git_tools.git_diff(root=filter_repo)
    assert not marker.exists()


@pytest.mark.parametrize("tool", ["status", "diff"])
@pytest.mark.parametrize("head_only", [False, True])
def test_submodule_inspection_is_refused_before_nested_helpers(
    filter_repo, tool, head_only
):
    child = filter_repo / "child"
    _git(filter_repo, "init", "-q", str(child))
    (child / "tracked.txt").write_text("before\n", encoding="utf-8")
    (child / ".gitattributes").write_text(
        "tracked.txt filter=guard\n", encoding="utf-8"
    )
    _git(child, "add", ".")
    _commit(child)
    (filter_repo / ".gitmodules").write_text(
        '[submodule "child"]\n\tpath = child\n\turl = ./child\n', encoding="utf-8"
    )
    _git(filter_repo, "add", "child", ".gitmodules")
    if head_only:
        _commit(filter_repo)
        _git(filter_repo, "update-index", "--force-remove", "child")
    command, marker = _helper(child, "clean")
    _git(child, "config", "filter.guard.clean", command)
    (child / "tracked.txt").write_text("after!\n", encoding="utf-8")
    os.utime(child / "tracked.txt", (1_600_000_000, 1_600_000_000))
    if not head_only:
        argv = (
            ["status", "--porcelain=v1", "--branch"]
            if tool == "status"
            else ["diff", "--no-ext-diff", "--no-textconv"]
        )
        git_tools._run_git(filter_repo, argv)
        assert marker.exists(), "the parent inspection must exercise the nested helper"
        marker.unlink()
    with pytest.raises(git_tools.GitCommandError, match="submodule helper safety"):
        _inspect(filter_repo, tool)
    assert not marker.exists()


@pytest.mark.parametrize("mechanism", ["external-diff", "textconv", "fsmonitor"])
def test_adjacent_helper_protections_remain_effective(filter_repo, mechanism):
    command, marker = _helper(filter_repo, "process")
    if mechanism == "external-diff":
        _git(filter_repo, "config", "diff.external", command)
    elif mechanism == "textconv":
        _git(filter_repo, "config", "diff.guarded.textconv", command)
        (filter_repo / ".gitattributes").write_text(
            "tracked.txt diff=guarded\n", encoding="utf-8"
        )
    else:
        _git(filter_repo, "config", "core.fsmonitor", command)
    for tool in ("status", "diff"):
        _inspect(filter_repo, tool)
        assert not marker.exists()


@pytest.mark.parametrize("no_lazy_fetch", ["0", "1"])
def test_missing_promisor_object_cannot_start_transport_helper(
    filter_repo, monkeypatch, no_lazy_fetch
):
    _commit(filter_repo)
    blob = _git(filter_repo, "rev-parse", "HEAD:tracked.txt").strip()
    object_path = filter_repo / ".git/objects" / blob[:2] / blob[2:]
    object_path.chmod(0o600)  # Git marks loose objects read-only on Windows.
    object_path.unlink()
    command, marker = _transport_helper(filter_repo)
    _git(filter_repo, "config", "remote.origin.url", "ssh://example.invalid/repo")
    _git(filter_repo, "config", "remote.origin.promisor", "true")
    _git(filter_repo, "config", "core.sshCommand", command)
    _git(filter_repo, "config", "protocol.ssh.allow", "always")
    with monkeypatch.context() as baseline_patch:
        baseline_patch.setitem(git_tools._GIT_ENV_EXTRA, "GIT_NO_LAZY_FETCH", "0")
        baseline_patch.setitem(git_tools._GIT_ENV_EXTRA, "GIT_ALLOW_PROTOCOL", "ssh")
        git_tools._run_git(filter_repo, ["diff", "--no-ext-diff", "--no-textconv"])
    assert marker.exists(), (
        "a missing promisor object must exercise the transport trigger"
    )
    marker.unlink()
    monkeypatch.setitem(git_tools._GIT_ENV_EXTRA, "GIT_NO_LAZY_FETCH", no_lazy_fetch)
    with pytest.raises(git_tools.GitCommandError):
        git_tools.git_diff(root=filter_repo)
    assert not marker.exists()


@pytest.mark.parametrize("stage", ["config", "ls-files", "ls-tree", "check-attr"])
@pytest.mark.parametrize("failure", ["truncated", "stderr", "failed"])
def test_incomplete_preflight_never_runs_final_inspection(
    filter_repo, monkeypatch, stage, failure
):
    _commit(filter_repo)
    _git(filter_repo, "config", "filter.unused.clean", "private command /secret/path")
    original = git_tools._run_git
    commands = []

    def fail_preflight(root, args, **kwargs):
        commands.append(args)
        if args[0] == stage:
            return git_tools._RunGitResult(
                returncode=2 if failure == "failed" else 0,
                stdout="private output",
                stderr="private stderr" if failure == "stderr" else "",
                stdout_truncated=failure == "truncated",
                stdout_dropped_bytes=0,
            )
        return original(root, args, **kwargs)

    monkeypatch.setattr(git_tools, "_run_git", fail_preflight)
    with pytest.raises(git_tools.GitCommandError, match="safety inspection") as error:
        git_tools.git_diff(root=filter_repo)
    assert "private" not in str(error.value)
    assert not any("diff" in args for args in commands)


@pytest.mark.parametrize(
    "raw", ["filter.guard.clean\ncommand", "filter.guard.clean\0", "broken\nvalue\0"]
)
def test_malformed_filter_metadata_is_refused(raw):
    with pytest.raises(git_tools.GitCommandError):
        git_tools._executable_filter_drivers(raw)


def test_filter_metadata_bounds_and_last_value_precedence(monkeypatch):
    raw = "filter.guard.clean\ncommand\0filter.guard.clean\n\0"
    assert git_tools._executable_filter_drivers(raw) == set()
    assert git_tools._executable_filter_drivers(
        "filter.guard.process\nprocess\0" + raw
    ) == {"guard"}
    monkeypatch.setattr(git_tools, "GIT_MAX_FILTER_CONFIG_ENTRIES", 1)
    with pytest.raises(git_tools.GitCommandError, match="safe limits"):
        git_tools._executable_filter_drivers(raw)


def test_preflight_deadline_fails_before_launch(filter_repo, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("expired safety inspection must not launch another process")

    monkeypatch.setattr(git_tools, "_run_git", unexpected)
    with pytest.raises(TimeoutError, match="safety inspection timed out"):
        git_tools._preflight_output(filter_repo, ["config"], 0)


@pytest.mark.parametrize(
    "raw", ["", "wrong\0filter\0unspecified\0", "tracked.txt\0other\0guard\0"]
)
def test_missing_or_mismatched_attribute_results_fail_closed(
    filter_repo, monkeypatch, raw
):
    _git(filter_repo, "config", "filter.unused.clean", "private command")
    original = git_tools._run_git

    def malformed(root, args, **kwargs):
        if args[0] == "check-attr":
            return git_tools._RunGitResult(0, raw, "", False, 0)
        assert "diff" not in args
        return original(root, args, **kwargs)

    monkeypatch.setattr(git_tools, "_run_git", malformed)
    with pytest.raises(git_tools.GitCommandError, match="attribute inspection"):
        git_tools.git_diff(root=filter_repo)


def test_tracked_file_scan_bound_prevents_inspection(filter_repo, monkeypatch):
    monkeypatch.setattr(git_tools, "GIT_MAX_FILTER_SCAN_ENTRIES", 1)
    with pytest.raises(git_tools.GitCommandError, match="safe limits"):
        git_tools.git_status(root=filter_repo)


def test_attribute_batches_are_complete_and_bounded(filter_repo, monkeypatch):
    _git(filter_repo, "config", "filter.unused.clean", "private command")
    monkeypatch.setattr(git_tools, "GIT_MAX_ATTRIBUTE_BATCH_CHARS", 15)
    original = git_tools._run_git
    batches = []

    def inspect_batch(root, args, **kwargs):
        if args[0] == "check-attr":
            batches.append(args[4:])
            assert sum(len(path.encode("utf-8")) + 1 for path in args[4:]) <= 15
        return original(root, args, **kwargs)

    monkeypatch.setattr(git_tools, "_run_git", inspect_batch)
    git_tools.git_diff(root=filter_repo)
    assert sorted(path for batch in batches for path in batch) == [
        ".gitattributes",
        "tracked.txt",
    ]
    assert len(batches) == 2


def test_filter_guard_argument_limit_fails_closed(filter_repo, monkeypatch):
    _git(filter_repo, "config", "filter.unused.clean", "private command")
    monkeypatch.setattr(git_tools, "GIT_MAX_FILTER_OPTION_CHARS", 1)
    with pytest.raises(git_tools.GitCommandError, match="safe invocation limits"):
        git_tools.git_diff(root=filter_repo)


def test_case_sensitive_driver_names_are_not_conflated(filter_repo):
    command, marker = _helper(filter_repo, "clean")
    _git(filter_repo, "config", "filter.GUARD.clean", command)
    assert not git_tools.git_status(root=filter_repo).clean
    assert not marker.exists()


@pytest.mark.parametrize("operation", ["clean", "process"])
def test_staged_diff_does_not_require_worktree_filters(filter_repo, operation):
    command, marker = _helper(filter_repo, operation)
    _git(filter_repo, "config", f"filter.guard.{operation}", command)
    result = git_tools.git_diff(staged=True, root=filter_repo)
    assert "+original" in result.raw
    assert not marker.exists()


@pytest.mark.parametrize("operation", ["clean", "process"])
def test_path_scoped_diff_allows_unrelated_tracked_filter(filter_repo, operation):
    command, marker = _helper(filter_repo, operation)
    _git(filter_repo, "config", f"filter.guard.{operation}", command)
    (filter_repo / "safe.txt").write_text("old\n", encoding="utf-8")
    _git(filter_repo, "add", "safe.txt")
    (filter_repo / "safe.txt").write_text("new\n", encoding="utf-8")
    result = git_tools.git_diff(path="safe.txt", root=filter_repo)
    assert "+new" in result.raw and "-old" in result.raw
    assert not marker.exists()
    with pytest.raises(
        git_tools.GitCommandError, match="executable clean/process filter"
    ):
        git_tools.git_diff(path="*.txt", root=filter_repo)
    assert not marker.exists()
