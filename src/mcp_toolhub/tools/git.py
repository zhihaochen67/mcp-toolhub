"""Dedicated read-only Git MCP tools.

These tools run a fixed, hard-coded set of git subcommands with
``shell=False`` inside the ToolHub workspace (or a test-supplied repository
root). They expose no arbitrary git arguments, never modify repository state,
and enforce the same workspace-containment rules as the rest of ToolHub.

Hardening against untrusted repositories
----------------------------------------
Every git subprocess is launched with the same read-only posture:

* ``--no-optional-locks`` and ``GIT_OPTIONAL_LOCKS=0`` — git must not take
  optional locks or write opportunistic state (index refresh, untracked
  cache, fsmonitor updates).
* ``-c core.fsmonitor=false`` — a repository (or system) config enabling
  core.fsmonitor must never cause a fsmonitor hook/daemon process to run
  during supposedly read-only inspection.
* ``--no-pager`` plus ``GIT_PAGER=cat`` — no interactive pager.
* ``GIT_TERMINAL_PROMPT=0`` — no interactive prompting.
* ``--no-ext-diff`` / ``--no-textconv`` (diff) — repository-configured
  external diff helpers and textconv filters never execute.
* ``stdin=DEVNULL``, ``capture_output=True``, ``shell=False``, a hard
  timeout, and bounded output for everything else.

Repository-boundary containment
-------------------------------
Before running status/diff, the tools discover the actual Git worktree root
with a hardened ``git rev-parse --show-toplevel`` and resolve it to a
canonical path. The root must be the workspace root itself or a descendant
of it. A parent repository outside the workspace (for example the ToolHub
source repository when the workspace directory itself is not a repository)
is rejected with ``Git repository root escapes ToolHub workspace`` so no
``../``-prefixed parent-repository paths can leak through the tools.
Nested repositories entirely inside the workspace remain valid when the tool
is addressed at that repository's location.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from mcp_toolhub.observability import audit
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.paths import get_workspace_root, is_portably_rooted_path

GIT_TIMEOUT_SECONDS = 20
GIT_MAX_OUTPUT_CHARS = 20_000
GIT_MAX_ERROR_CHARS = 500

# Global options applied to every read-only git subprocess. These must come
# before the subcommand.
_GIT_GLOBAL_ARGS = (
    "--no-optional-locks",
    "--no-pager",
    "-c",
    "core.fsmonitor=false",
)

# Environment applied to every read-only git subprocess (defense in depth
# alongside the equivalent command-line options above).
_GIT_ENV_EXTRA = {
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat",
}


class GitStatusEntry(BaseModel):
    code: str
    path: str


class GitStatusResult(BaseModel):
    path: str
    branch: str | None = None
    clean: bool
    entries: list[GitStatusEntry]
    raw: str


class GitDiffResult(BaseModel):
    path: str | None
    staged: bool
    additions: int | None = None
    deletions: int | None = None
    binary: bool = False
    raw: str


GIT_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    open_world_hint=False,
)


def _truncate(value: str, limit: int = GIT_MAX_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value

    return value[:limit] + f"\n...[+{len(value) - limit} chars truncated]"


def _resolve_repo_path(root: Path, path: str) -> Path:
    """Resolve a repository-relative path and guarantee it stays inside the
    repository root (rejecting absolute paths and ``..`` escapes)."""
    candidate = Path(path)

    if is_portably_rooted_path(path):
        raise ValueError(f"Absolute paths are not allowed: {path}")

    resolved_root = root.resolve()
    target = (root / candidate).resolve()

    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"Access denied: path escapes repository: {path}") from exc

    return target


def _run_git(root: Path, argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a git subcommand with the hardened read-only posture."""
    located = shutil.which("git")
    if located is None:
        raise ValueError("Git executable not found")
    try:
        git_executable = Path(located).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Git executable could not be resolved") from exc

    command = [str(git_executable), *_GIT_GLOBAL_ARGS, *argv]
    environment = build_execution_environment(
        additional_variables=_GIT_ENV_EXTRA
    ).environment()

    try:
        return subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValueError("Git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"git {' '.join(argv)} timed out after {GIT_TIMEOUT_SECONDS}s"
        ) from exc


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _audit_failure(
    trace_id: str,
    tool: str,
    arguments: dict,
    error: str,
    error_type: str,
    duration_ms: int,
) -> None:
    audit.record_event(
        trace_id=trace_id,
        tool=tool,
        action="failure",
        executed=False,
        success=False,
        duration_ms=duration_ms,
        arguments=arguments,
        cwd=".",
        error=error,
        error_type=error_type,
    )


class GitCommandError(ValueError):
    """git exited non-zero or produced unusable output."""


class GitWorkspaceError(ValueError):
    """The discovered Git worktree root lies outside the ToolHub workspace."""


def _git_error(completed: subprocess.CompletedProcess[str]) -> GitCommandError:
    stderr = completed.stderr.strip() or "git failed"
    detail = _truncate(stderr, GIT_MAX_ERROR_CHARS)
    return GitCommandError(f"git exited {completed.returncode}: {detail}")


def _audit_error_type(exc: BaseException) -> str:
    if isinstance(exc, GitWorkspaceError):
        return "WorkspaceBoundaryViolation"
    if isinstance(exc, GitCommandError):
        return "GitError"
    return type(exc).__name__


def _discover_worktree_root(root: Path) -> Path:
    """Find the actual Git worktree root with a hardened fixed invocation of
    ``git rev-parse --show-toplevel``, resolved to a canonical Path.

    Raises ``GitCommandError`` when the directory is not inside any Git
    repository.
    """
    completed = _run_git(root, ["rev-parse", "--show-toplevel"])

    if completed.returncode != 0:
        raise _git_error(completed)

    top_level = completed.stdout.strip()
    if not top_level:
        raise GitCommandError("git rev-parse --show-toplevel produced no output")

    return Path(top_level).resolve()


def _require_contained_worktree(worktree_root: Path, boundary: Path) -> Path:
    """Enforce repository-root containment.

    The resolved worktree root must be equal to the boundary (the workspace
    root, in production) or a descendant of it. A parent repository outside
    the boundary — for example the ToolHub source repository ``.git`` when
    the workspace itself is not a repository — is rejected so that no
    parent-repository data (``../...`` paths) can leak through the tools.
    """
    boundary = boundary.resolve()
    worktree_root = worktree_root.resolve()

    try:
        worktree_root.relative_to(boundary)
    except ValueError as exc:
        raise GitWorkspaceError(
            f"Git repository root escapes ToolHub workspace: {worktree_root}"
        ) from exc

    return worktree_root


def _parse_status(raw: str) -> tuple[str | None, list[GitStatusEntry]]:
    branch: str | None = None
    entries: list[GitStatusEntry] = []

    for line in raw.splitlines():
        if not line:
            continue

        if line.startswith("## "):
            part = line[3:]
            part = part.removeprefix("No commits yet on ")
            branch = part.split("...", 1)[0].split(" [", 1)[0].strip()
            continue

        if len(line) >= 3:
            entries.append(GitStatusEntry(code=line[:2], path=line[3:].strip()))

    return branch, entries


def _count_diff(raw: str) -> tuple[int | None, int | None, bool]:
    if "Binary files" in raw:
        return None, None, True

    additions = 0
    deletions = 0

    for line in raw.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1

    return additions, deletions, False


def git_status(root: Path | None = None) -> GitStatusResult:
    """Read-only ``git status`` for the workspace repository.

    The actual Git worktree root is discovered first (hardened
    ``rev-parse --show-toplevel``) and must be the workspace root itself or
    a descendant of it; otherwise the call is rejected so parent-repository
    data can never leak through.
    """
    trace_id = audit.new_trace_id()
    started = time.monotonic()
    repo_root = root or get_workspace_root()
    arguments = {"subcommand": "status"}

    try:
        worktree_root = _require_contained_worktree(
            _discover_worktree_root(repo_root),
            repo_root,
        )
    except (ValueError, TimeoutError) as exc:
        _audit_failure(
            trace_id,
            "git.status",
            arguments,
            str(exc),
            _audit_error_type(exc),
            _elapsed_ms(started),
        )
        raise

    try:
        completed = _run_git(worktree_root, ["status", "--porcelain=v1", "--branch"])
    except (ValueError, TimeoutError) as exc:
        _audit_failure(
            trace_id,
            "git.status",
            arguments,
            str(exc),
            _audit_error_type(exc),
            _elapsed_ms(started),
        )
        raise

    duration_ms = _elapsed_ms(started)

    if completed.returncode != 0:
        error = _git_error(completed)
        _audit_failure(
            trace_id,
            "git.status",
            arguments,
            str(error),
            _audit_error_type(error),
            duration_ms,
        )
        raise error

    branch, entries = _parse_status(completed.stdout)

    audit.record_event(
        trace_id=trace_id,
        tool="git.status",
        action="read",
        executed=True,
        success=True,
        duration_ms=duration_ms,
        returncode=0,
        arguments={"branch": branch, "entries": len(entries)},
        cwd=".",
    )

    return GitStatusResult(
        path=".",
        branch=branch,
        clean=not entries,
        entries=entries,
        raw=_truncate(completed.stdout),
    )


def git_diff(
    path: str | None = None,
    staged: bool = False,
    root: Path | None = None,
) -> GitDiffResult:
    """Read-only ``git diff`` (optionally ``--cached`` and path-filtered).

    No arbitrary git arguments are accepted: only a repository-relative
    ``path`` and a ``staged`` flag. The actual Git worktree root is
    discovered first (hardened ``rev-parse --show-toplevel``) and must be
    the workspace root itself or a descendant of it; otherwise the call is
    rejected so parent-repository data can never leak through.
    """
    trace_id = audit.new_trace_id()
    started = time.monotonic()
    repo_root = root or get_workspace_root()
    arguments = {"path": path, "staged": staged}

    # --no-ext-diff / --no-textconv prevent external diff helpers and
    # textconv filters (potentially configured in .gitattributes) from
    # executing arbitrary commands during a supposedly read-only inspection.
    argv = ["diff", "--no-ext-diff", "--no-textconv"]

    if staged:
        argv.append("--cached")

    try:
        worktree_root = _require_contained_worktree(
            _discover_worktree_root(repo_root),
            repo_root,
        )

        if path is not None:
            _resolve_repo_path(worktree_root, path)  # raises on escape
            argv += ["--", path]

    except (ValueError, TimeoutError) as exc:
        _audit_failure(
            trace_id,
            "git.diff",
            arguments,
            str(exc),
            _audit_error_type(exc),
            _elapsed_ms(started),
        )
        raise

    try:
        completed = _run_git(worktree_root, argv)
    except (ValueError, TimeoutError) as exc:
        _audit_failure(
            trace_id,
            "git.diff",
            arguments,
            str(exc),
            _audit_error_type(exc),
            _elapsed_ms(started),
        )
        raise

    duration_ms = _elapsed_ms(started)

    if completed.returncode != 0:
        error = _git_error(completed)
        _audit_failure(
            trace_id,
            "git.diff",
            arguments,
            str(error),
            _audit_error_type(error),
            duration_ms,
        )
        raise error

    raw = _truncate(completed.stdout)
    additions, deletions, binary = _count_diff(raw)

    audit.record_event(
        trace_id=trace_id,
        tool="git.diff",
        action="read",
        executed=True,
        success=True,
        duration_ms=duration_ms,
        returncode=0,
        arguments={
            "path": path,
            "staged": staged,
            "additions": additions,
            "deletions": deletions,
        },
        cwd=".",
    )

    return GitDiffResult(
        path=path,
        staged=staged,
        additions=additions,
        deletions=deletions,
        binary=binary,
        raw=raw,
    )


def register_git_tools(mcp: MCPServer) -> None:
    """Register the read-only Git tools."""

    @mcp.tool(
        name="git.status",
        title="Show git working tree status",
        annotations=GIT_ANNOTATIONS,
    )
    def status() -> GitStatusResult:
        """Read-only git status of the ToolHub workspace repository."""
        return git_status()

    @mcp.tool(
        name="git.diff",
        title="Show git diff",
        annotations=GIT_ANNOTATIONS,
    )
    def diff(path: str | None = None, staged: bool = False) -> GitDiffResult:
        """Read-only git diff. Never modifies repository state.

        Args:
            path: Optional repository-relative path to filter the diff.
            staged: Show staged changes (git diff --cached) instead of
                unstaged ones.
        """
        return git_diff(path=path, staged=staged)
