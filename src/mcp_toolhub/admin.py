"""Trusted local administrator CLI for the Approval Engine.

This runs as a separate process from the MCP server and is the *only* way to
approve or reject approval requests. It is intended for a human operator, not
the MCP agent: the agent has no tool that can reach this code path.

Usage:
    mcp-toolhub-admin list
    mcp-toolhub-admin approve <request_id>
    mcp-toolhub-admin reject <request_id>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from mcp_toolhub import __version__
from mcp_toolhub.security import approval
from mcp_toolhub.security.approval import ApprovalRequest, ApprovalStatus
from mcp_toolhub.security.executable_snapshot import (
    parse_executable_snapshot,
    validate_executable_snapshot,
)
from mcp_toolhub.security.paths import (
    RuntimeConfigurationError,
    initialize_runtime_configuration,
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _describe_mutation(request: ApprovalRequest) -> str:
    """Bounded metadata for a mutation approval — never the content/patch."""
    payload = request.payload or {}
    path = str(payload.get("path", "?"))

    lines = [f"  mutation:     {request.kind} path={path}"]

    if request.kind == "file_write":
        content = payload.get("content")
        if isinstance(content, str):
            lines.append(
                f"  content:      {len(content)} chars, sha256={_sha256_text(content)}"
            )
        lines.append(f"  expected:     sha256={payload.get('expected_hash')}")
        lines.append(f"  parents:      {bool(payload.get('create_parents'))}")

    elif request.kind == "file_patch":
        patch = payload.get("patch")
        if isinstance(patch, str):
            lines.append(
                f"  patch:        {len(patch)} chars, sha256={_sha256_text(patch)}"
            )
        lines.append(f"  expected:     sha256={payload.get('expected_hash')}")

    return "\n".join(lines)


def _json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _describe_shell(request: ApprovalRequest) -> str:
    """Render exact shell request fields without shell-quoting ambiguity."""
    lines = [
        "  kind:                 shell",
        f"  requested_program:    {_json_string(request.program)}",
    ]

    try:
        snapshot = parse_executable_snapshot(request.payload.get("executable_snapshot"))
    except (TypeError, ValueError) as exc:
        lines.append(f"  executable_snapshot:  INVALID ({exc})")
    else:
        lines.extend(
            [
                f"  resolved_executable:  {_json_string(str(snapshot.path))}",
                f"  executable_sha256:    {snapshot.sha256}",
                f"  executable_size:      {snapshot.size} bytes",
            ]
        )

    lines.extend(
        [
            f"  cwd:                  {_json_string(request.cwd)}",
            f"  argument_count:       {len(request.args)}",
        ]
    )
    lines.extend(
        f"  args[{index}]:              {_json_string(argument)}"
        for index, argument in enumerate(request.args)
    )
    lines.append("  identity_scope:       primary executable only")
    return "\n".join(lines)


def _format_request(request: ApprovalRequest) -> str:
    decided = request.decided_at.isoformat() if request.decided_at else "-"

    lines = [
        request.request_id,
        f"  status:       {request.status.value}",
    ]

    if request.kind == "shell":
        lines.append(_describe_shell(request))
    else:
        lines.append(f"  kind:         {request.kind}")
        lines.append(_describe_mutation(request))

    lines.append(f"  risk:         {request.risk.value} ({request.risk_reason})")
    lines.append(f"  created_at:   {request.created_at.isoformat()}")
    lines.append(f"  expires_at:   {request.expires_at.isoformat()}")
    lines.append(f"  decided_at:   {decided}")

    return "\n".join(lines)


def cmd_list(args: argparse.Namespace) -> int:
    requests = approval.list_requests()

    if not requests:
        print("No approval requests.")
        return 0

    for request in requests:
        print(_format_request(request))
        print()

    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    request = approval.get_request(args.request_id)
    if request is None:
        print(f"error: Unknown approval request: {args.request_id}", file=sys.stderr)
        return 1

    print("Approval candidate:")
    print(_format_request(request))

    if request.status != ApprovalStatus.PENDING:
        print(
            f"error: Approval request is {request.status.value}: {request.request_id}",
            file=sys.stderr,
        )
        return 1

    if request.kind == "shell":
        try:
            validate_executable_snapshot(request.payload.get("executable_snapshot"))
        except (TypeError, ValueError) as exc:
            print(f"error: Invalid executable snapshot: {exc}", file=sys.stderr)
            return 1

    try:
        confirmation = input(f"Type APPROVE to approve {request.request_id}: ")
    except EOFError:
        confirmation = ""

    if confirmation != "APPROVE":
        print("Approval cancelled.", file=sys.stderr)
        return 1

    try:
        request = approval.approve_request(args.request_id)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Approved {request.request_id}.")
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    try:
        request = approval.reject_request(args.request_id)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Rejected {request.request_id}.")
    print(_format_request(request))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-toolhub-admin",
        description="Trusted local administrator CLI for MCP ToolHub approvals.",
    )
    parser.add_argument("--version", action="version", version=__version__)

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "list",
        help="List all approval requests.",
    ).set_defaults(func=cmd_list)

    approve = subparsers.add_parser(
        "approve",
        help="Approve a pending request.",
    )
    approve.add_argument("request_id", help="Approval request ID to approve.")
    approve.set_defaults(func=cmd_approve)

    reject = subparsers.add_parser(
        "reject",
        help="Reject a pending request.",
    )
    reject.add_argument("request_id", help="Approval request ID to reject.")
    reject.set_defaults(func=cmd_reject)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        initialize_runtime_configuration()
    except RuntimeConfigurationError as exc:
        print(f"mcp-toolhub-admin: {exc}", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
