"""Example: a *safe* MCP server.

Exposes ``read_allowed_file`` which only reads files inside this directory's
``data/`` folder. All paths are resolved and compared against the allowlist;
traversal attempts are rejected.

This server is what `mcp-guard scan` / `fuzz` should treat as **PASS**.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the example helper importable when run as `python server.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _mcp_lite import register_tool, serve, server_info

HERE = Path(__file__).resolve().parent
DATA_DIR = (HERE / "data").resolve()

server_info("safe-example", "0.1.0")


@register_tool(
    name="read_allowed_file",
    description="Read a UTF-8 file from the allowlisted `data/` directory.",
    input_schema={
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "File name inside data/ (basename only).",
                "maxLength": 64,
                "pattern": "^[A-Za-z0-9_.-]+$",
            }
        },
        "required": ["filename"],
        "additionalProperties": False,
    },
    annotations={"readOnlyHint": True, "destructiveHint": False, "title": "Read allowlisted file"},
)
def read_allowed_file(args):
    filename = args.get("filename")
    if not isinstance(filename, str) or not filename:
        return {"content": [{"type": "text", "text": "filename required"}], "isError": True}
    # basename check + canonical containment.
    if os.sep in filename or "/" in filename or "\\" in filename or filename.startswith(".."):
        return {"content": [{"type": "text", "text": "filename must be a basename"}], "isError": True}
    candidate = (DATA_DIR / filename).resolve()
    try:
        candidate.relative_to(DATA_DIR)
    except ValueError:
        return {"content": [{"type": "text", "text": "access denied"}], "isError": True}
    if not candidate.exists() or not candidate.is_file():
        return {"content": [{"type": "text", "text": "not found"}], "isError": True}
    return {"content": [{"type": "text", "text": candidate.read_text(encoding="utf-8")}]}


@register_tool(
    name="list_allowed_files",
    description="List file names inside the allowlisted data directory.",
    input_schema={
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    annotations={"readOnlyHint": True, "destructiveHint": False, "title": "List allowlisted files"},
)
def list_allowed_files(_args):
    if not DATA_DIR.exists():
        return {"content": [{"type": "text", "text": "[]"}]}
    names = sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    return {"content": [{"type": "text", "text": "\n".join(names)}]}


if __name__ == "__main__":
    serve()
