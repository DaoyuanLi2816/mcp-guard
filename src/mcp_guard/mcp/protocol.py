"""Protocol-level constants and request/response builders.

Kept transport-agnostic so the same builders can be reused by a future
Streamable HTTP transport.
"""

from __future__ import annotations

import itertools
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "mcp-guard"
CLIENT_VERSION = "0.1.0"


def initialize_params(client_name: str = CLIENT_NAME, client_version: str = CLIENT_VERSION) -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "roots": {"listChanged": False},
            "sampling": {},
            "experimental": {},
        },
        "clientInfo": {"name": client_name, "version": client_version},
    }


def initialized_notification() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}


_id_counter = itertools.count(1)


def next_id() -> int:
    return next(_id_counter)


def build_request(method: str, params: dict[str, Any], *, request_id: int | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id if request_id is not None else next_id(),
        "method": method,
        "params": params,
    }


def build_notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def is_response_for(msg: dict[str, Any], request_id: int) -> bool:
    return msg.get("jsonrpc") == "2.0" and msg.get("id") == request_id and (
        "result" in msg or "error" in msg
    )


def parse_error(response: dict[str, Any]) -> str | None:
    err = response.get("error")
    if not err:
        return None
    if isinstance(err, dict):
        return f"{err.get('code')}: {err.get('message')}"
    return str(err)


def parse_tool_result_text(result: Any) -> str:
    """Coerce a tools/call ``result`` into the text the user would see."""
    if not isinstance(result, dict):
        return str(result)
    if result.get("structuredContent"):
        out = str(result["structuredContent"])
    else:
        out = ""
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    out += "\n" + item["text"] if out else item["text"]
                elif item.get("type") in {"image", "resource"}:
                    out += f"\n<{item.get('type')}>"
                else:
                    out += "\n" + str(item)
    if "isError" in result and result.get("isError"):
        out = f"[ERROR]\n{out}" if out else "[ERROR]"
    return out
