"""Shared test fixtures.

Every test runs against an isolated approval store and audit log so that the
real ``.toolhub/approvals.json`` / ``.toolhub/audit.jsonl`` are never touched
and tests do not interfere with each other.

Note: this file deliberately avoids pytest's ``tmp_path``/``tmp_path_factory``
fixtures. Under the DSH Windows file sandbox those fixtures create their
basetemp directory with an empty DACL, which makes ``os.scandir`` fail with a
permission error. We manage our own per-test temp directory instead.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_TMP_ROOT = Path(__file__).resolve().parents[1] / ".test-tmp"


def _rmtree(path: Path) -> None:
    """Remove a tree, clearing the Windows read-only attribute that git sets
    on files inside ``.git`` so repos can actually be deleted."""

    def remove_readonly(func, failed_path, _exc_info):
        try:
            os.chmod(failed_path, stat.S_IWRITE)
            func(failed_path)
        except OSError:
            pass

    shutil.rmtree(path, onerror=remove_readonly)


def _new_temp_dir(prefix: str) -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    # Path.mkdir() (default mode), NOT tempfile.mkdtemp(): under the DSH
    # sandbox, directories created with mode 0o700 end up with an empty DACL.
    path = _TMP_ROOT / f"{prefix}-{secrets.token_hex(8)}"
    path.mkdir()
    return path


@pytest.fixture(autouse=True)
def isolated_approval_store(monkeypatch):
    from toolhub.security.paths import _reset_workspace_configuration_for_tests

    store_dir = _new_temp_dir("approvals")
    store = store_dir / "approvals.json"
    audit_log = store_dir / "audit.jsonl"

    monkeypatch.setenv("TOOLHUB_APPROVAL_STORE", str(store))
    monkeypatch.setenv("TOOLHUB_APPROVAL_TTL_SECONDS", "300")
    monkeypatch.setenv("TOOLHUB_AUDIT_PATH", str(audit_log))
    monkeypatch.delenv("TOOLHUB_WORKSPACE_ROOT", raising=False)
    _reset_workspace_configuration_for_tests()

    yield store

    _reset_workspace_configuration_for_tests()
    _rmtree(store_dir)


@pytest.fixture
def temp_dir():
    path = _new_temp_dir("dir")
    yield path
    _rmtree(path)


@pytest.fixture
def git_repo(temp_dir):
    """A real, freshly initialized temporary Git repository."""
    subprocess.run(
        ["git", "init", "-q", str(temp_dir)],
        capture_output=True,
        text=True,
        check=True,
    )
    return temp_dir


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.fixture
def run_git():
    """Run a git command inside a test repository (setup helper)."""
    return _git
