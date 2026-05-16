"""Filesystem helpers used across scanners and fuzzers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path | str) -> Any:
    """Read a JSON file. Raises ``ValueError`` with a friendly message on
    parse failure so the CLI can surface it without a traceback."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise ValueError(f"File not found: {p}") from e
    except OSError as e:
        raise ValueError(f"Could not read {p}: {e}") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {p}: {e}") from e


def write_text(path: Path | str, content: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def looks_like_mcp_config(data: Any) -> bool:
    """Return True if *data* looks like a Claude/Cursor style MCP config."""
    if not isinstance(data, dict):
        return False
    if "mcpServers" in data or "servers" in data:
        return True
    # Single-server form: {"command": [...], "args": [...]} or similar.
    return any(k in data for k in ("command", "transport", "args"))


def project_root() -> Path:
    """The directory the user ran ``mcp-guard`` from. Cwd is good enough."""
    return Path.cwd().resolve()
