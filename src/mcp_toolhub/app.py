from mcp.server import MCPServer

from mcp_toolhub import __version__
from mcp_toolhub.security.paths import (
    RuntimeConfiguration,
    initialize_runtime_configuration,
)
from mcp_toolhub.tools.audit import register_audit_tools
from mcp_toolhub.tools.filesystem import register_filesystem_tools
from mcp_toolhub.tools.git import register_git_tools
from mcp_toolhub.tools.shell import register_shell_tools


def create_server(configuration: RuntimeConfiguration | None = None) -> MCPServer:
    """Create a configured stdio-capable ToolHub MCP server."""

    initialize_runtime_configuration(configuration)
    server = MCPServer(
        "MCP ToolHub",
        version=__version__,
        instructions=(
            "A secure tool execution gateway for AI agents. "
            "Filesystem access is restricted to the configured workspace."
        ),
    )

    @server.tool(name="toolhub.ping")
    def ping(message: str = "hello") -> dict[str, str]:
        """Check whether MCP ToolHub is running correctly."""

        return {
            "status": "ok",
            "service": "mcp-toolhub",
            "echo": message,
        }

    register_filesystem_tools(server)
    register_shell_tools(server)
    register_git_tools(server)
    register_audit_tools(server)
    return server
