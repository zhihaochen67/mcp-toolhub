from mcp.server import MCPServer

from toolhub.tools.filesystem import register_filesystem_tools
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