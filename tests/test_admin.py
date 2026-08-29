"""Focused tests for the trusted administrator approval display."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_toolhub import admin
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalStatus
from mcp_toolhub.security.executable_snapshot import fingerprint_executable
from mcp_toolhub.security.paths import get_workspace_root
from mcp_toolhub.security.risk import RiskLevel

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
        assert json.dumps(str(get_workspace_root()), ensure_ascii=True) in displayed
        assert json.dumps(request.program, ensure_ascii=True) in displayed
        assert json.dumps(str(executable.resolve()), ensure_ascii=True) in displayed
        assert snapshot["sha256"] in displayed
        assert f"{snapshot['size']} bytes" in displayed
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


def test_admin_help_includes_trusted_maintenance_commands(capsys):
    parser = admin.build_parser()

    assert "prune" in parser.format_help()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["prune", "--help"])

    assert exc_info.value.code == 0
    help_output = capsys.readouterr().out
    assert "approvals" in help_output
    assert "audit" in help_output


def test_admin_approval_prune_is_dry_run_by_default_and_hides_payload(
    isolated_approval_store,
    capsys,
):
    current = datetime.now(UTC) - timedelta(days=30)
    sentinel = "TOP-SECRET-MAINTENANCE-PAYLOAD-71c3"
    request = approval.create_request(
        kind="file_write",
        payload={
            "workspace_root": str(get_workspace_root()),
            "path": "secret.txt",
            "content": sentinel,
        },
        risk=RiskLevel.HIGH,
        risk_reason="test",
        now=current,
    )
    approval.reject_request(request.request_id, now=current + timedelta(minutes=1))
    before = isolated_approval_store.read_bytes()

    assert admin.main(["prune", "approvals", "--older-than-days", "10"]) == 0

    output = capsys.readouterr().out
    assert "DRY RUN approvals" in output
    assert "eligible=1" in output
    assert sentinel not in output
    assert request.request_id not in output
    assert isolated_approval_store.read_bytes() == before


def test_admin_approval_prune_apply_removes_old_terminal_request(capsys):
    current = datetime.now(UTC) - timedelta(days=30)
    request = approval.create_request(
        risk=RiskLevel.MEDIUM,
        risk_reason="test",
        now=current,
    )
    approval.reject_request(request.request_id, now=current + timedelta(minutes=1))

    assert (
        admin.main(
            [
                "prune",
                "approvals",
                "--older-than-days",
                "10",
                "--apply",
            ]
        )
        == 0
    )

    assert "APPLY approvals" in capsys.readouterr().out
    assert approval.get_request(request.request_id) is None


def test_admin_audit_prune_dry_run_and_apply(capsys):
    from mcp_toolhub.observability import audit

    for index in range(3):
        assert audit.record_event(tool="admin-test", action=str(index)) is True
    path = audit._default_audit_path()
    before = path.read_bytes()

    assert admin.main(["prune", "audit", "--keep-last", "1"]) == 0
    assert "DRY RUN audit" in capsys.readouterr().out
    assert path.read_bytes() == before

    assert admin.main(["prune", "audit", "--keep-last", "1", "--apply"]) == 0
    assert "APPLY audit" in capsys.readouterr().out
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_existing_admin_list_and_reject_semantics_remain_available(capsys):
    request = approval.create_request(
        risk=RiskLevel.MEDIUM,
        risk_reason="test",
    )

    assert admin.main(["list"]) == 0
    assert request.request_id in capsys.readouterr().out
    assert admin.main(["reject", request.request_id]) == 0
    assert approval.get_request(request.request_id).status == ApprovalStatus.REJECTED
