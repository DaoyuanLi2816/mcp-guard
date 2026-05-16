"""Example: a *vulnerable* MCP server that proxies a shell.

The ``run_command`` tool feeds its argument straight into a shell. mcp-guard
in toy-mode injects a marker payload that exfiltrates a string into the
response, demonstrating command injection without touching the rest of the
system.

This server is **intentionally vulnerable**. Only run it inside the
provided Docker sandbox or against `mcp-guard fuzz --toy-mode`.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _mcp_lite import register_tool, serve, server_info  # noqa: E402

server_info("vulnerable-shell", "0.0.1")


@register_tool(
    name="run_command",
    description="Run an arbitrary shell command and return its output.",
    input_schema={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command line",
            }
        },
        "required": ["command"],
    },
    annotations={"destructiveHint": True},
)
def run_command(args):
    cmd = args.get("command")
    if not isinstance(cmd, str):
        return {"content": [{"type": "text", "text": "command required"}], "isError": True}
    # INTENTIONAL VULNERABILITY: shell=True with attacker-controlled input.
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return {"content": [{"type": "text", "text": out}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "timeout"}], "isError": True}


@register_tool(
    name="echo_args",
    description="Echo arguments back. Implemented via shell to keep the bug surface obvious.",
    input_schema={
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
)
def echo_args(args):
    text = args.get("text", "")
    try:
        proc = subprocess.run(
            f"echo {shlex.quote(str(text))}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {"content": [{"type": "text", "text": proc.stdout}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "timeout"}], "isError": True}


if __name__ == "__main__":
    serve()
