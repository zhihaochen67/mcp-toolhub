from mcp.server import MCPServer

from toolhub.security.paths import initialize_workspace_configuration

# Validate and freeze process-level configuration before any MCP tools are
# imported or registered. Direct library use remains lazy for testability.
initialize_workspace_configuration()

from toolhub.tools.audit import register_audit_tools
from toolhub.tools.filesystem import register_filesystem_tools
from toolhub.tools.git import register_git_tools
from toolhub.tools.shell import register_shell_tools

mcp = MCPServer(
    "MCP ToolHub",
    instructions=(
        "A secure tool execution gateway for AI agents. "
        "Filesystem access is restricted to the configured workspace."
    ),
)


@mcp.tool(name="toolhub.ping")
def ping(message: str = "hello") -> dict[str, str]:
    """Check whether MCP ToolHub is running correctly."""

    return {
        "status": "ok",
        "service": "mcp-toolhub",
        "echo": message,
    }


register_filesystem_tools(mcp)
register_shell_tools(mcp)
register_git_tools(mcp)
register_audit_tools(mcp)
