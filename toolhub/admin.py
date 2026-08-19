"""Trusted local administrator CLI for the Approval Engine.

This runs as a separate process from the MCP server and is the *only* way to
approve or reject approval requests. It is intended for a human operator, not
the MCP agent: the agent has no tool that can reach this code path.

Usage:
    uv run python -m toolhub.admin list
    uv run python -m toolhub.admin approve <request_id>
    uv run python -m toolhub.admin reject <request_id>
"""

from __future__ import annotations

import argparse
import hashlib
import sys

from toolhub.security import approval
from toolhub.security.approval import ApprovalRequest


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


def _format_request(request: ApprovalRequest) -> str:
    decided = request.decided_at.isoformat() if request.decided_at else "-"

    lines = [
        request.request_id,
        f"  status:       {request.status.value}",
    ]

    if request.kind == "shell":
        args = " ".join(request.args) if request.args else ""
        lines.append(f"  kind:         shell")
        lines.append(f"  command:      {request.program} {args}".rstrip())
        lines.append(f"  cwd:          {request.cwd}")
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
    try:
        request = approval.approve_request(args.request_id)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Approved {request.request_id}.")
    print(_format_request(request))
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
        prog="toolhub.admin",
        description="Trusted local administrator CLI for MCP ToolHub approvals.",
    )

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
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
