"""High-level facade. ``connect_stdio`` and ``McpStdioClient`` are re-exported
here so callers can write ``from mcp_guard.mcp.client import ...``."""

from __future__ import annotations

from .stdio_client import MCPClientError, McpStdioClient, connect_stdio

__all__ = ["MCPClientError", "McpStdioClient", "connect_stdio"]
