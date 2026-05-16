"""Tiny JSON-RPC over stdio framework used by the bundled example servers.

This is a TEST fixture only. It implements just enough of the MCP wire
format for `mcp-guard inspect`/`fuzz` to exercise the servers without
pulling in the full MCP SDK as a hard runtime dependency.

The framework is intentionally minimal:

- Read newline-delimited JSON from stdin.
- Dispatch ``initialize``, ``tools/list``, ``tools/call``.
- Respond on stdout (also newline-delimited JSON).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

_TOOL_FNS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}
_TOOL_SPECS: list[dict[str, Any]] = []
_SERVER_INFO = {"name": "example", "version": "0.0.1"}


def server_info(name: str, version: str) -> None:
    global _SERVER_INFO
    _SERVER_INFO = {"name": name, "version": version}


def register_tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    annotations: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> Callable[[Callable[[dict[str, Any]], dict[str, Any]]], Callable[[dict[str, Any]], dict[str, Any]]]:
    """Decorator: register a tool implementation by name."""

    def decorator(fn: Callable[[dict[str, Any]], dict[str, Any]]):
        _TOOL_FNS[name] = fn
        spec = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }
        if annotations:
            spec["annotations"] = annotations
        if output_schema:
            spec["outputSchema"] = output_schema
        _TOOL_SPECS.append(spec)
        return fn

    return decorator


def _write(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _ok(id_: Any, result: Any) -> None:
    _write({"jsonrpc": "2.0", "id": id_, "result": result})


def _err(id_: Any, code: int, message: str) -> None:
    _write({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def _text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        payload["isError"] = True
    return payload


def serve() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        id_ = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            _ok(
                id_,
                {
                    "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "serverInfo": _SERVER_INFO,
                    "capabilities": {"tools": {"listChanged": False}},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _ok(id_, {"tools": _TOOL_SPECS})
        elif method == "tools/call":
            tname = params.get("name")
            args = params.get("arguments") or {}
            fn = _TOOL_FNS.get(tname or "")
            if not fn:
                _err(id_, -32601, f"Tool not found: {tname}")
                continue
            try:
                result = fn(args if isinstance(args, dict) else {})
                if isinstance(result, dict) and ("content" in result or "isError" in result):
                    _ok(id_, result)
                else:
                    _ok(id_, _text_result(str(result)))
            except Exception as e:
                _ok(id_, _text_result(f"{type(e).__name__}: {e}", is_error=True))
        elif id_ is not None:
            _err(id_, -32601, f"Method not implemented: {method}")
