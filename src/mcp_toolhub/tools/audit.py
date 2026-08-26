"""MCP surface for the audit subsystem: a strictly read-only recent-events API.

There is deliberately no audit delete/edit tool. The agent can only read a
bounded number of already-sanitized audit events; it cannot name a file, so
no arbitrary file access is possible through this tool.
"""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from mcp_toolhub.observability import audit


class AuditRecentResult(BaseModel):
    count: int
    events: list[dict]


AUDIT_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    open_world_hint=False,
)


def register_audit_tools(mcp: MCPServer) -> None:
    """Register the read-only audit API tools."""

    @mcp.tool(
        name="toolhub.audit_recent",
        title="Recent audit events",
        annotations=AUDIT_ANNOTATIONS,
    )
    def audit_recent(limit: int = 20) -> AuditRecentResult:
        """Return the most recent sanitized audit events (max 100).

        Read-only: returns bounded metadata summaries. Event contents are
        already sanitized at write time; no raw stdout/stderr or secrets are
        included.
        """
        events = audit.read_recent(limit=limit)
        return AuditRecentResult(count=len(events), events=events)
