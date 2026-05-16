"""Scanner for MCP server config files (mcp.json, claude_desktop_config.json,
single-server JSON, etc) and ad-hoc start commands."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Iterable

from ..constants import DANGEROUS_START_PATTERNS
from ..models import Finding, Location
from ..utils.paths import load_json
from .risk_rules import make_finding
from .secrets import env_value_looks_secret, find_secrets, redact

_SHELL_BINARIES = {"sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_SHELL_EXEC_FLAGS = {"-c", "/c", "/C"}
_BROAD_DIRECTORY_TOKENS = {"/", "~", "$HOME", "**", "*"}


def _iter_command_strings(command: Any, args: Any) -> Iterable[str]:
    if isinstance(command, str):
        yield command
    elif isinstance(command, list):
        for c in command:
            if isinstance(c, str):
                yield c
    if isinstance(args, list):
        for c in args:
            if isinstance(c, str):
                yield c


def _full_command_line(command: Any, args: Any) -> str:
    parts: list[str] = []
    if isinstance(command, str):
        parts.append(command)
    elif isinstance(command, list):
        parts.extend(str(c) for c in command)
    if isinstance(args, list):
        parts.extend(str(a) for a in args)
    return " ".join(parts)


def _starts_with_shell(tokens: list[str]) -> bool:
    if not tokens:
        return False
    head = Path(tokens[0]).name.lower()
    if head not in _SHELL_BINARIES:
        return False
    return any(t in _SHELL_EXEC_FLAGS for t in tokens[1:3])


def _argv(command: Any, args: Any) -> list[str]:
    out: list[str] = []
    if isinstance(command, str):
        try:
            out.extend(shlex.split(command, posix=True))
        except ValueError:
            out.append(command)
    elif isinstance(command, list):
        out.extend(str(c) for c in command)
    if isinstance(args, list):
        out.extend(str(a) for a in args)
    return out


def _scan_command(command: Any, args: Any, location: Location) -> list[Finding]:
    findings: list[Finding] = []
    command_line = _full_command_line(command, args)
    if not command_line.strip():
        return findings

    tokens = _argv(command, args)

    if _starts_with_shell(tokens):
        findings.append(
            make_finding(
                "MCPG001",
                description=(
                    "The start command is interpreted by a shell. Shell "
                    "metacharacters in arguments will be expanded before the "
                    "MCP server runs."
                ),
                evidence=command_line,
                location=location,
                confidence=0.9,
            )
        )

    for pattern, rule_id in DANGEROUS_START_PATTERNS:
        if re.search(pattern, command_line, re.IGNORECASE):
            findings.append(
                make_finding(
                    rule_id,
                    description=f"Detected dangerous token in start command: {pattern!r}.",
                    evidence=command_line,
                    location=location,
                    confidence=0.9,
                )
            )

    # python -c / node -e / ruby -e — inline interpreter execution.
    if len(tokens) >= 3:
        interp = Path(tokens[0]).name.lower()
        flag = tokens[1]
        if (interp.startswith("python") and flag == "-c") or (
            interp.startswith("node") and flag == "-e"
        ) or (interp == "ruby" and flag == "-e"):
            findings.append(
                make_finding(
                    "MCPG001",
                    description=(
                        f"Inline {interp} code in start command ({flag})."
                        " Inline interpreter execution should be replaced by a real script."
                    ),
                    evidence=command_line,
                    location=location,
                    confidence=0.85,
                )
            )

    # Direct env reference to docker socket / sensitive locations.
    for s in _iter_command_strings(command, args):
        if "/var/run/docker.sock" in s:
            findings.append(
                make_finding(
                    "MCPG033",
                    description="Docker socket referenced in start command.",
                    evidence=s,
                    location=location,
                )
            )
        if "--privileged" in s:
            findings.append(
                make_finding(
                    "MCPG034",
                    description="`--privileged` flag in start command.",
                    evidence=s,
                    location=location,
                )
            )

    return findings


def _scan_env(env: Any, location: Location) -> list[Finding]:
    if not isinstance(env, dict):
        return []
    findings: list[Finding] = []
    for k, v in env.items():
        if not isinstance(k, str):
            continue
        if env_value_looks_secret(k, v):
            evidence = f"{k}={redact(str(v))}"
            findings.append(
                make_finding(
                    "MCPG006",
                    description=f"Environment variable `{k}` appears to contain a plaintext secret.",
                    evidence=evidence,
                    location=location.model_copy(update={"parameter": k}),
                    confidence=0.7 if not find_secrets(str(v)) else 0.95,
                )
            )
    return findings


def _scan_transport(server: dict[str, Any], location: Location) -> list[Finding]:
    findings: list[Finding] = []
    transport = (server.get("transport") or server.get("type") or "stdio")
    if isinstance(transport, str):
        transport_l = transport.lower()
    else:
        transport_l = "stdio"

    if transport_l in {"http", "sse", "streamable-http", "websocket", "ws"}:
        url = server.get("url") or server.get("endpoint")
        host = server.get("host")
        bind = ""
        if isinstance(url, str):
            bind += url
        if isinstance(host, str):
            bind += " " + host
        bound_publicly = bool(
            re.search(r"(?:^|[/@])0\.0\.0\.0(?::\d+)?", bind)
            or re.search(r"\b0\.0\.0\.0\b", bind)
            or re.search(r"\[::\](?::\d+)?", bind)
        )
        if bound_publicly:
            findings.append(
                make_finding(
                    "MCPG007",
                    description="HTTP/SSE transport is bound to 0.0.0.0.",
                    evidence=str(url or host),
                    location=location,
                )
            )
        auth = server.get("auth") or server.get("authorization") or server.get("headers")
        has_token = False
        if isinstance(auth, dict):
            for v in auth.values():
                if isinstance(v, str) and ("bearer" in v.lower() or "token" in v.lower() or len(v) >= 16):
                    has_token = True
        elif isinstance(auth, str) and len(auth) >= 16:
            has_token = True
        elif isinstance(server.get("headers"), dict):
            for hk, hv in server["headers"].items():
                if isinstance(hk, str) and hk.lower() == "authorization" and isinstance(hv, str):
                    has_token = True
        if not has_token:
            findings.append(
                make_finding(
                    "MCPG008",
                    description=(
                        f"{transport_l.upper()} transport has no detectable authentication."
                    ),
                    evidence=str(url or host or transport_l),
                    location=location,
                )
            )

    # Directory allowlist over-scoping.
    for key in ("allowedDirectories", "allowed_directories", "directories", "roots"):
        value = server.get(key)
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, str) and entry.strip() in _BROAD_DIRECTORY_TOKENS:
                    findings.append(
                        make_finding(
                            "MCPG009",
                            description=(
                                f"`{key}` allows a very broad path (`{entry}`)."
                            ),
                            evidence=f"{key}={value}",
                            location=location.model_copy(update={"parameter": key}),
                        )
                    )
                if isinstance(entry, str) and (entry.endswith("$HOME") or entry == "~"):
                    findings.append(
                        make_finding(
                            "MCPG009",
                            description=f"`{key}` mounts the home directory (`{entry}`).",
                            evidence=f"{key}={value}",
                            location=location.model_copy(update={"parameter": key}),
                        )
                    )
    return findings


def _normalize_servers(data: Any) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("mcpServers"), dict):
        return [(k, v) for k, v in data["mcpServers"].items() if isinstance(v, dict)]
    if isinstance(data.get("servers"), dict):
        return [(k, v) for k, v in data["servers"].items() if isinstance(v, dict)]
    # Single-server form.
    if any(k in data for k in ("command", "args", "transport", "url")):
        return [(str(data.get("name") or "default"), data)]
    return []


def scan_config(data: Any, *, source: str = "<inline>") -> list[Finding]:
    """Scan a parsed MCP config dict. *source* is used in finding locations."""
    findings: list[Finding] = []
    servers = _normalize_servers(data)
    if not servers:
        return findings
    for name, server in servers:
        location = Location(target=source, path=source, tool=None, parameter=name)
        command = server.get("command")
        args = server.get("args")
        findings.extend(_scan_command(command, args, location))
        findings.extend(_scan_env(server.get("env"), location))
        findings.extend(_scan_transport(server, location))
    return findings


def scan_config_file(path: Path | str) -> list[Finding]:
    p = Path(path)
    data = load_json(p)
    return scan_config(data, source=str(p))


def scan_ad_hoc_command(command_line: str) -> list[Finding]:
    """Scan a single command line passed via ``--command``."""
    try:
        tokens = shlex.split(command_line, posix=True)
    except ValueError:
        tokens = command_line.split()
    return _scan_command(tokens, None, Location(target=command_line, path="<command>"))
