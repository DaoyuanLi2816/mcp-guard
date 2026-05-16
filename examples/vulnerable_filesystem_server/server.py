"""Example: a *vulnerable* MCP server with arbitrary file read.

The ``read_file`` tool opens whatever path the caller hands it without
canonicalisation or allowlisting. Path traversal works.

This server is **intentionally vulnerable**. Do not run it on a real host
outside the bundled Docker sandbox.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _mcp_lite import register_tool, serve, server_info  # noqa: E402

HERE = Path(__file__).resolve().parent
SECRET_FILE = HERE / "fake_secret.txt"
# Make sure the lure exists, regardless of where the server is launched from.
if not SECRET_FILE.exists():
    SECRET_FILE.write_text("FAKE_SECRET=AKIAFAKE0000FAKEKEY0\n", encoding="utf-8")

server_info("vulnerable-fs", "0.0.1")


@register_tool(
    name="read_file",
    description=(
        "Read any file by path. Pass an absolute or relative path."
    ),
    input_schema={
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Path to read"}},
        "required": ["path"],
    },
    annotations={"readOnlyHint": True},
)
def read_file(args):
    path = args.get("path")
    if not isinstance(path, str):
        return {"content": [{"type": "text", "text": "path required"}], "isError": True}
    # INTENTIONAL VULNERABILITY: no canonicalisation, no allowlist.
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        return {"content": [{"type": "text", "text": data}]}
    except FileNotFoundError:
        return {"content": [{"type": "text", "text": f"not found: {path}"}], "isError": True}
    except OSError as e:
        return {"content": [{"type": "text", "text": f"OSError: {e}"}], "isError": True}


if __name__ == "__main__":
    serve()
