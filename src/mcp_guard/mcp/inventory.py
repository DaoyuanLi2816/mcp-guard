"""Resolve a CLI target (config file, ``--command``, or project dir) into a
runnable spec and produce an :class:`Inventory`."""

from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..constants import DEFAULT_TIMEOUTS
from ..models import Finding, Inventory, Location, ServerInfo, ToolSpec
from ..scanner.risk_rules import make_finding
from ..utils.logging import get_logger
from ..utils.paths import load_json, looks_like_mcp_config
from .client import MCPClientError, connect_stdio

log = get_logger()


@dataclass
class ServerSpec:
    name: str
    transport: str
    argv: list[str] | None = None
    cwd: Path | None = None
    env: dict[str, str] | None = None
    url: str | None = None
    source: str = "<inline>"

    def display_command(self) -> str:
        if self.argv:
            return " ".join(self.argv)
        if self.url:
            return self.url
        return self.name


def _spec_from_server_dict(name: str, server: dict[str, Any], source: str) -> ServerSpec:
    transport = (server.get("transport") or server.get("type") or "stdio")
    argv: list[str] | None = None
    if "command" in server or "args" in server:
        command = server.get("command")
        args = server.get("args") or []
        argv = []
        if isinstance(command, str):
            # `command` in mcp.json is conventionally a single executable name
            # (e.g. "python"), so don't try to shlex-split it.
            argv.append(command)
        elif isinstance(command, list):
            argv.extend(str(c) for c in command)
        if isinstance(args, list):
            argv.extend(str(a) for a in args)
    cwd = None
    if isinstance(server.get("cwd"), str):
        cwd = Path(server["cwd"])
    env = None
    if isinstance(server.get("env"), dict):
        env = {str(k): str(v) for k, v in server["env"].items()}
    url = server.get("url") or server.get("endpoint")
    return ServerSpec(
        name=name,
        transport=transport if isinstance(transport, str) else "stdio",
        argv=argv,
        cwd=cwd,
        env=env,
        url=url if isinstance(url, str) else None,
        source=source,
    )


def _split_cmdline(cmd: str) -> list[str]:
    """``shlex.split`` that does the right thing on Windows.

    POSIX mode treats backslashes as escapes, which mangles Windows paths.
    Non-POSIX mode preserves backslashes but keeps quotes; we strip them.
    """
    if sys.platform.startswith("win"):
        try:
            raw = shlex.split(cmd, posix=False)
        except ValueError:
            raw = cmd.split()
        return [t.strip('"').strip("'") for t in raw]
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def resolve_specs_from_target(
    target: str | Path,
    *,
    command_override: str | None = None,
) -> list[ServerSpec]:
    """Translate a CLI target into one or more ServerSpec objects."""
    if command_override:
        argv = _split_cmdline(command_override)
        return [ServerSpec(name="cli-command", transport="stdio", argv=argv, source="<command>")]

    p = Path(target)
    if p.is_file():
        try:
            data = load_json(p)
        except ValueError:
            return []
        if isinstance(data, dict) and "mcpServers" in data:
            return [
                _spec_from_server_dict(n, s, str(p))
                for n, s in data["mcpServers"].items()
                if isinstance(s, dict)
            ]
        if isinstance(data, dict) and "servers" in data:
            return [
                _spec_from_server_dict(n, s, str(p))
                for n, s in data["servers"].items()
                if isinstance(s, dict)
            ]
        if looks_like_mcp_config(data):
            return [_spec_from_server_dict("default", data, str(p))]
        return []
    if p.is_dir():
        # Look for an mcp.json next to the project.
        candidate = p / "mcp.json"
        if candidate.exists():
            return resolve_specs_from_target(candidate)
    return []


def build_inventory_from_config(spec: ServerSpec) -> tuple[Inventory | None, list[Finding]]:
    """Static inventory (no live connection). Returns ``(inventory, findings)``."""
    inv = Inventory(
        target=spec.source,
        transport=spec.transport,
        command=spec.argv,
        env_keys=sorted(spec.env or {}),
    )
    return inv, []


def inspect_target(
    spec: ServerSpec,
    *,
    timeout: float = DEFAULT_TIMEOUTS["initialize"],
) -> tuple[Inventory, list[Finding]]:
    """Live-inspect *spec* by launching it as a stdio child."""
    inventory = Inventory(
        target=spec.source,
        transport=spec.transport,
        command=spec.argv,
        env_keys=sorted(spec.env or {}),
    )
    findings: list[Finding] = []
    if spec.transport != "stdio" or not spec.argv:
        # Live HTTP/SSE inspection is on the roadmap; for now return the
        # static skeleton with a clear note.
        inventory.warnings.append(
            f"Live inspection for transport `{spec.transport}` is not yet "
            "supported; only static analysis was performed."
        )
        return inventory, findings

    client = None
    try:
        client = connect_stdio(spec.argv, cwd=spec.cwd, env=spec.env, default_timeout=timeout)
        try:
            client.initialize(timeout=timeout)
        except MCPClientError as e:
            findings.append(
                make_finding(
                    "MCPG035",
                    description=f"initialize failed: {e}",
                    location=Location(target=spec.source),
                    confidence=0.95,
                )
            )
            return inventory, findings
        try:
            tools = client.tools_list(timeout=timeout)
        except MCPClientError as e:
            findings.append(
                make_finding(
                    "MCPG035",
                    description=f"tools/list failed: {e}",
                    location=Location(target=spec.source),
                    confidence=0.9,
                )
            )
            tools = []
        for t in tools:
            if not isinstance(t, dict) or not t.get("name"):
                continue
            inventory.tools.append(
                ToolSpec(
                    name=str(t["name"]),
                    description=t.get("description"),
                    input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                    output_schema=t.get("outputSchema") or t.get("output_schema"),
                    annotations=t.get("annotations") or {},
                )
            )
        info = client.server_info
        inventory.server_info = ServerInfo(
            name=info.get("name") if isinstance(info, dict) else None,
            version=info.get("version") if isinstance(info, dict) else None,
        )
        inventory.capabilities = client.capabilities
        inventory.protocol_version = client.protocol_version
        inventory.warnings.extend(client.protocol_warnings)
    finally:
        if client is not None:
            client.close()

    return inventory, findings
