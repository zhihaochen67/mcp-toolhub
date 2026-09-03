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
* ``stdin=DEVNULL``, ``shell=False``, a hard timeout, and continuously
  drained, memory-bounded output capture for everything else (excess output
  is discarded while the pipes are still read, so Git can never fill an OS
  pipe buffer and block).

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
import time
from dataclasses import dataclass
from pathlib import Path

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from mcp_toolhub.observability import audit
from mcp_toolhub.security.execution_environment import build_execution_environment
from mcp_toolhub.security.paths import (
    get_workspace_root,
    has_portable_parent_reference,
    is_portably_rooted_path,
)
from mcp_toolhub.security.process_containment import (
    ProcessContainmentError,
    run_contained_process,
)

GIT_TIMEOUT_SECONDS = 20
GIT_MAX_OUTPUT_CHARS = 20_000
GIT_MAX_ERROR_CHARS = 500
GIT_MAX_STATUS_ENTRIES = 1_024
GIT_MAX_PATH_CHARS = 4_096

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


@dataclass(frozen=True)
class _RunGitResult:
    """Bounded outcome of one contained read-only git subprocess."""

    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stdout_dropped_bytes: int


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


def _format_raw_output(
    value: str,
    *,
    capture_truncated: bool,
    dropped_bytes: int,
) -> str:
    """Apply the public Git character limit, then report discarded bytes.

    When the containment layer retained the complete stream this preserves the
    existing character-based truncation marker exactly.  When containment
    already discarded output beyond its retention cap, the returned value
    instead carries a single deterministic discarded-byte marker (the public
    20_000-character prefix limit still applies).
    """
    if not capture_truncated:
        return _truncate(value)

    if len(value) > GIT_MAX_OUTPUT_CHARS:
        kept = value[:GIT_MAX_OUTPUT_CHARS]
        char_cut_bytes = len(value.encode("utf-8", errors="replace")) - len(
            kept.encode("utf-8", errors="replace")
        )
    else:
        kept = value
        char_cut_bytes = 0

    discarded = dropped_bytes + max(0, char_cut_bytes)
    return kept + f"\n...[+{discarded} output bytes discarded]"


def _resolve_repo_path(root: Path, path: str) -> Path:
    """Resolve a repository-relative path and guarantee it stays inside the
    repository root (rejecting absolute paths and ``..`` escapes)."""
    if not isinstance(path, str) or "\0" in path:
        raise ValueError("Repository path is malformed")
    candidate = Path(path)

    if is_portably_rooted_path(path):
        raise ValueError(f"Absolute paths are not allowed: {path}")
    if has_portable_parent_reference(path):
        raise ValueError("Access denied: path traversal escapes repository boundary")
    if len(path) > GIT_MAX_PATH_CHARS:
        raise ValueError("Repository path exceeds the maximum length")

    try:
        resolved_root = root.resolve(strict=True)
        target = (resolved_root / candidate).resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError("Repository path could not be resolved safely") from exc

    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("Access denied: path escapes repository") from exc

    return target


def _run_git(root: Path, argv: list[str]) -> _RunGitResult:
    """Run a git subcommand with the hardened read-only posture."""
    located = shutil.which("git")
    if located is None:
        raise ValueError("Git executable not found")
    try:
        git_executable = Path(located).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Git executable could not be resolved") from exc

    environment = build_execution_environment(
        additional_variables=_GIT_ENV_EXTRA
    ).environment()

    try:
        result = run_contained_process(
            str(git_executable),
            [*_GIT_GLOBAL_ARGS, *argv],
            cwd=root,
            env=environment,
            timeout_seconds=GIT_TIMEOUT_SECONDS,
        )
    except ProcessContainmentError as exc:
        raise ValueError(
            "Git execution could not use the required process-tree containment."
        ) from exc
    except FileNotFoundError as exc:
        raise ValueError("Git executable not found") from exc
    except OSError as exc:
        raise ValueError(
            "Git execution could not use the required process-tree containment."
        ) from exc
    if result.timed_out:
        raise TimeoutError(f"Git command timed out after {GIT_TIMEOUT_SECONDS}s")
    if result.returncode is None:
        raise ValueError("Git execution did not return a process exit status.")
    return _RunGitResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        stdout_truncated=result.stdout_stats.truncated,
        stdout_dropped_bytes=result.stdout_stats.dropped_bytes,
    )


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


def _git_error(completed: _RunGitResult) -> GitCommandError:
    # Git stderr can contain repository paths, config values, or helper
    # diagnostics. Preserve the exit status without reflecting that untrusted
    # stream through MCP or the audit tool.
    return GitCommandError(f"git exited {completed.returncode}: command failed")


def _audit_error_type(exc: BaseException) -> str:
    if isinstance(exc, GitWorkspaceError):
        return "WorkspaceBoundaryViolation"
    if isinstance(exc, GitCommandError):
        return "GitError"
    return type(exc).__name__


def _resolve_repository_boundary(root: Path) -> Path:
    """Canonicalize an internal repository boundary before process launch."""

    try:
        boundary = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GitWorkspaceError(
            "Git workspace boundary could not be resolved safely"
        ) from exc
    if not boundary.is_dir():
        raise GitWorkspaceError("Git workspace boundary is not a directory")
    return boundary


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
    if (
        completed.stdout_truncated
        or "\0" in top_level
        or "\n" in top_level
        or "\r" in top_level
        or len(top_level) > GIT_MAX_PATH_CHARS
        or not Path(top_level).is_absolute()
    ):
        raise GitCommandError("git returned an invalid repository root")

    try:
        discovered = Path(top_level).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GitCommandError("git returned an invalid repository root") from exc
    if not discovered.is_dir():
        raise GitCommandError("git returned an invalid repository root")
    return discovered


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
            "Git repository root escapes ToolHub workspace"
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
            candidate = part.split("...", 1)[0].split(" [", 1)[0].strip()
            if len(candidate) > GIT_MAX_PATH_CHARS:
                raise GitCommandError("git status branch output exceeds safe limits")
            branch = candidate
            continue

        if len(line) >= 3:
            if len(entries) >= GIT_MAX_STATUS_ENTRIES:
                raise GitCommandError("git status contains too many entries")
            if len(line) > GIT_MAX_PATH_CHARS + 3:
                raise GitCommandError("git status path output exceeds safe limits")
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
        repo_root = _resolve_repository_boundary(repo_root)
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

    try:
        branch, entries = _parse_status(completed.stdout)
    except ValueError as exc:
        _audit_failure(
            trace_id,
            "git.status",
            arguments,
            str(exc),
            _audit_error_type(exc),
            duration_ms,
        )
        raise

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
        raw=_format_raw_output(
            completed.stdout,
            capture_truncated=completed.stdout_truncated,
            dropped_bytes=completed.stdout_dropped_bytes,
        ),
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
        repo_root = _resolve_repository_boundary(repo_root)
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

    raw = _format_raw_output(
        completed.stdout,
        capture_truncated=completed.stdout_truncated,
        dropped_bytes=completed.stdout_dropped_bytes,
    )
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
