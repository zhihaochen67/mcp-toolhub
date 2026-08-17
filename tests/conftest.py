"""Shared test fixtures.

Every test runs against an isolated approval store so that the real
``.toolhub/approvals.json`` is never touched and tests do not interfere with
each other.

Note: this file deliberately avoids pytest's ``tmp_path``/``tmp_path_factory``
fixtures. Under the DSH Windows file sandbox those fixtures create their
basetemp directory with an empty DACL, which makes ``os.scandir`` fail with a
permission error. We manage our own per-test temp directory instead.
"""

from __future__ import annotations

import secrets
import shutil
from pathlib import Path

import pytest

_TMP_ROOT = Path(__file__).resolve().parents[1] / ".test-tmp"


@pytest.fixture(autouse=True)
def isolated_approval_store(monkeypatch):
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    # Path.mkdir() (default mode), NOT tempfile.mkdtemp(): under the DSH
    # sandbox, directories created with mode 0o700 end up with an empty DACL.
    store_dir = _TMP_ROOT / f"approvals-{secrets.token_hex(8)}"
    store_dir.mkdir()
    store = store_dir / "approvals.json"

    monkeypatch.setenv("TOOLHUB_APPROVAL_STORE", str(store))
    monkeypatch.setenv("TOOLHUB_APPROVAL_TTL_SECONDS", "300")

    yield store

    shutil.rmtree(store_dir, ignore_errors=True)
