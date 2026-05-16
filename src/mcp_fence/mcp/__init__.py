"""MCP client + inventory helpers."""

from .client import MCPClientError, McpStdioClient, connect_stdio
from .inventory import build_inventory_from_config, inspect_target

__all__ = [
    "MCPClientError",
    "McpStdioClient",
    "build_inventory_from_config",
    "connect_stdio",
    "inspect_target",
]
