"""Focused tests for the trusted administrator approval display."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolhub import admin
from toolhub.security import approval
from toolhub.security.approval import ApprovalStatus
from toolhub.security.executable_snapshot import fingerprint_executable
from toolhub.security.paths import get_workspace_root
from toolhub.security.risk import RiskLevel

_DEFAULT_SNAPSHOT = object()


def _shell_request(
    executable: Path,
    *,
    program: str = "requested tool",
    args: list[str] | None = None,
    snapshot_override: object = _DEFAULT_SNAPSHOT,
):
    snapshot = fingerprint_executable(executable).to_payload()
    if snapshot_override is not _DEFAULT_SNAPSHOT:
        snapshot = snapshot_override
    return approval.create_request(
        program=program,
        args=list(args or []),
        cwd=".",
        risk=RiskLevel.HIGH,
        risk_reason="test",
        payload={
            "workspace_root": str(get_workspace_root()),
            "executable_snapshot": snapshot,
        },
    )


def test_shell_identity_is_shown_unambiguously_before_approval(
    temp_dir,
    monkeypatch,
    capsys,
):
    executable = temp_dir / "approved tool.exe"
    executable.write_bytes(b"approved executable")
    arguments = [
        "",
        "two words",
        'a "quote"',
        "C:\\tools\\path",
        "line\nbreak",
        "\x1bcontrol",
    ]
    request = _shell_request(executable, args=arguments)
    snapshot = request.payload["executable_snapshot"]

    def confirm(prompt):
        displayed = capsys.readouterr().out
        assert "Approval candidate:" in displayed
        assert json.dumps(request.program, ensure_ascii=True) in displayed
        assert json.dumps(str(executable.resolve()), ensure_ascii=True) in displayed
        assert snapshot["sha256"] in displayed
        assert f'{snapshot["size"]} bytes' in displayed
        assert 'cwd:                  "."' in displayed
        assert f"argument_count:       {len(arguments)}" in displayed
        for index, argument in enumerate(arguments):
            encoded = json.dumps(argument, ensure_ascii=True)
            assert f"args[{index}]:" in displayed
            assert encoded in displayed
        assert "identity_scope:       primary executable only" in displayed
        assert request.request_id in prompt
        return "APPROVE"

    monkeypatch.setattr("builtins.input", confirm)

    assert admin.main(["approve", request.request_id]) == 0
    assert approval.get_request(request.request_id).status == ApprovalStatus.APPROVED


@pytest.mark.parametrize(
    "snapshot_override",
    [
        None,
        {
            "canonical_path": "C:/not-authorized/tool.exe",
            "sha256": "not-a-valid-hash",
            "size": 1,
        },
    ],
    ids=["missing", "malformed"],
)
def test_invalid_shell_snapshot_cannot_be_approved(
    temp_dir,
    monkeypatch,
    capsys,
    snapshot_override,
):
    executable = temp_dir / "tool.exe"
    executable.write_bytes(b"approved executable")
    request = _shell_request(
        executable,
        snapshot_override=snapshot_override,
    )

    def unexpected_confirmation(_prompt):
        raise AssertionError("malformed snapshot must not reach confirmation")

    monkeypatch.setattr("builtins.input", unexpected_confirmation)

    assert admin.main(["approve", request.request_id]) == 1
    captured = capsys.readouterr()
    assert "executable_snapshot:  INVALID" in captured.out
    assert "Invalid executable snapshot" in captured.err
    assert approval.get_request(request.request_id).status == ApprovalStatus.PENDING


def test_declined_confirmation_leaves_request_pending(
    temp_dir,
    monkeypatch,
):
    executable = temp_dir / "tool.exe"
    executable.write_bytes(b"approved executable")
    request = _shell_request(executable)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    assert admin.main(["approve", request.request_id]) == 1
    assert approval.get_request(request.request_id).status == ApprovalStatus.PENDING
