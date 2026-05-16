"""Scanner for tool metadata and JSON schema risks.

Operates on an :class:`mcp_guard.models.Inventory` produced by the MCP
inspector. All checks are deterministic; the optional LLM judge augments
results via :mod:`mcp_guard.llm.local_judge`.
"""

from __future__ import annotations

import re
import unicodedata

from ..constants import (
    HIGH_RISK_PARAM_NAMES,
    OVERLY_BROAD_TOOL_NAMES,
    PROMPT_INJECTION_PHRASES,
    RCE_TOOL_NAME_TOKENS,
)
from ..models import Finding, Inventory, Location, ToolSpec
from ..utils.jsonschema import (
    get_string_constraints,
    is_object_schema,
    primitive_for,
    walk_properties,
)
from .risk_rules import make_finding

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_MARKDOWN_RE = re.compile(r"\[//\]:?\s*(?:#|<)\s*\(.*?\)", re.DOTALL)
_ZERO_WIDTH_RE = re.compile(r"[​-‏⁠⁡﻿]")
_KNOWN_TOOL_NAMES = {
    "read_file",
    "write_file",
    "list_dir",
    "search",
    "search_web",
    "fetch",
    "fetch_url",
    "list_files",
    "git_status",
    "git_diff",
    "run_tests",
    "shell",
    "bash",
}


_ASCII_HOMOGLYPH_SWAPS = [
    ("I", "l"),  # capital I vs lowercase L
    ("l", "I"),
    ("1", "l"),
    ("l", "1"),
    ("0", "O"),
    ("O", "0"),
    ("O", "o"),
    ("rn", "m"),  # `rn` reads as `m`
    ("vv", "w"),
]


def _ascii_confusable_match(name: str) -> str | None:
    """Detect ASCII homoglyph spoofing of well-known tool names."""
    if not name:
        return None
    lower = name.lower()
    # Single-character swaps.
    for old, new in _ASCII_HOMOGLYPH_SWAPS:
        if old not in name:
            continue
        cand = name.replace(old, new, 1)
        if cand != name and cand.lower() in _KNOWN_TOOL_NAMES:
            return cand.lower()
        cand_all = name.replace(old, new)
        if cand_all != name and cand_all.lower() in _KNOWN_TOOL_NAMES:
            return cand_all.lower()
    # Capital-in-position-0 of an otherwise lowercase identifier where the
    # lowercase form matches a known tool.
    if name[0].isupper() and name[1:].islower():
        # `Iist_files` -> `list_files`?
        for repl in ("l", "i", "1", "o", "0"):
            cand = repl + name[1:]
            if cand in _KNOWN_TOOL_NAMES:
                return cand
    # Lowercase form of the entire name matches a known tool exactly, but
    # the original has any uppercase letters (camelCase mimicry).
    if any(c.isupper() for c in name) and lower in _KNOWN_TOOL_NAMES and name != lower:
        return lower
    return None


def _has_confusable(name: str) -> tuple[bool, str | None]:
    """Return ``(yes, normalized)`` if *name* contains a likely confusable.

    Catches both unicode homoglyphs (e.g. Cyrillic `а` in a Latin word) and
    ASCII visual confusables like `Iist_files` vs `list_files`.
    """
    if not isinstance(name, str) or not name:
        return False, None
    if name.isascii():
        ascii_hit = _ascii_confusable_match(name)
        if ascii_hit:
            return True, ascii_hit
        return False, None
    normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    if normalized and normalized != name and normalized in _KNOWN_TOOL_NAMES:
        return True, normalized
    # Look for mixed scripts (Latin + Cyrillic, etc.).
    scripts: set[str] = set()
    for ch in name:
        if ch.isalpha():
            try:
                blk = unicodedata.name(ch).split()[0]
            except ValueError:
                continue
            scripts.add(blk)
    if "LATIN" in scripts and any(s not in {"LATIN", "DIGIT"} for s in scripts):
        return True, normalized or name
    return False, None


def _description_findings(tool: ToolSpec, location: Location) -> list[Finding]:
    out: list[Finding] = []
    desc = tool.description or ""
    if not desc:
        return out
    lower = desc.lower()
    matched_phrases: list[str] = []
    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase in lower:
            matched_phrases.append(phrase)
    if matched_phrases:
        out.append(
            make_finding(
                "MCPG010",
                description=(
                    "Tool description contains prompt-injection phrases: "
                    + ", ".join(repr(p) for p in matched_phrases[:5])
                ),
                evidence=desc[:300],
                location=location,
                confidence=0.9,
            )
        )
    if _HTML_COMMENT_RE.search(desc) or _HIDDEN_MARKDOWN_RE.search(desc):
        out.append(
            make_finding(
                "MCPG011",
                description="Tool description contains hidden HTML/markdown comments.",
                evidence=desc[:300],
                location=location,
                confidence=0.95,
            )
        )
    if _ZERO_WIDTH_RE.search(desc):
        out.append(
            make_finding(
                "MCPG011",
                description="Tool description contains zero-width / invisible characters.",
                evidence=repr(desc[:200]),
                location=location,
                confidence=0.95,
            )
        )
    if len(desc) > 1500 or desc.count("\n") > 25:
        out.append(
            make_finding(
                "MCPG024",
                description=f"Tool description is unusually long ({len(desc)} chars).",
                evidence=desc[:200] + "…",
                location=location,
                confidence=0.6,
            )
        )
    return out


def _name_findings(tool: ToolSpec, location: Location) -> list[Finding]:
    out: list[Finding] = []
    name = tool.name or ""
    if not name:
        return out
    lower = name.lower()
    confusable, normalized = _has_confusable(name)
    if confusable:
        out.append(
            make_finding(
                "MCPG012",
                description=(
                    f"Tool name {name!r} contains non-ASCII characters that "
                    f"look like {normalized!r}."
                ),
                evidence=name,
                location=location,
                confidence=0.85,
            )
        )
    if lower in OVERLY_BROAD_TOOL_NAMES:
        out.append(
            make_finding(
                "MCPG013",
                description=f"Tool name `{name}` is overly broad.",
                evidence=name,
                location=location,
                confidence=0.75,
            )
        )
    if any(tok in lower for tok in RCE_TOOL_NAME_TOKENS):
        out.append(
            make_finding(
                "MCPG023",
                description=f"Tool name `{name}` implies arbitrary code execution.",
                evidence=name,
                location=location,
                confidence=0.85,
            )
        )
    return out


def _annotation_findings(tool: ToolSpec, location: Location) -> list[Finding]:
    out: list[Finding] = []
    ann = tool.annotations or {}
    if not isinstance(ann, dict):
        return out
    schema = tool.input_schema or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    prop_names = set(props.keys()) if isinstance(props, dict) else set()
    read_only = bool(ann.get("readOnlyHint"))
    destructive = bool(ann.get("destructiveHint"))
    desc_lower = (tool.description or "").lower()

    # MCPG016 only fires for params whose name implies mutation, since a
    # read-only `filename` (e.g. for a constrained file reader) is fine.
    write_implying_params = {"command", "cmd", "shell", "exec", "code", "eval", "script", "webhook", "callback"}
    if read_only:
        bad = sorted(prop_names & write_implying_params)
        if bad:
            out.append(
                make_finding(
                    "MCPG016",
                    description=(
                        "Annotation `readOnlyHint=true` contradicts parameters "
                        + ", ".join(repr(b) for b in bad)
                    ),
                    evidence=str(ann),
                    location=location,
                    confidence=0.85,
                )
            )
        if any(tok in desc_lower for tok in ("write", "delete", "execute", "run command", "modify")):
            out.append(
                make_finding(
                    "MCPG014",
                    description=(
                        "Description suggests write/exec/delete but `readOnlyHint=true`."
                    ),
                    evidence=tool.description or "",
                    location=location,
                    confidence=0.7,
                )
            )

    if destructive:
        # Destructive should have schema guards.
        ap = schema.get("additionalProperties") if isinstance(schema, dict) else None
        if ap is not False:
            out.append(
                make_finding(
                    "MCPG015",
                    description=(
                        "Destructive tool does not restrict additionalProperties."
                    ),
                    evidence=f"additionalProperties={ap}",
                    location=location,
                )
            )
        if not schema.get("required"):
            out.append(
                make_finding(
                    "MCPG015",
                    description="Destructive tool has no required parameters.",
                    evidence=str(schema)[:200],
                    location=location,
                )
            )
    return out


def _schema_findings(tool: ToolSpec, location: Location) -> list[Finding]:
    out: list[Finding] = []
    schema = tool.input_schema or {}
    if not isinstance(schema, dict):
        return out
    risky_name = tool.name.lower() in OVERLY_BROAD_TOOL_NAMES or any(
        tok in tool.name.lower() for tok in RCE_TOOL_NAME_TOKENS
    )

    if not is_object_schema(schema) and schema:
        out.append(
            make_finding(
                "MCPG017",
                description="Tool inputSchema is not declared as `type: object`.",
                evidence=str(schema)[:200],
                location=location,
            )
        )

    props = schema.get("properties") if isinstance(schema, dict) else None
    ap = schema.get("additionalProperties") if isinstance(schema, dict) else None
    required = schema.get("required") if isinstance(schema, dict) else None

    if risky_name and ap is not False:
        out.append(
            make_finding(
                "MCPG019",
                description="High-risk tool allows additionalProperties.",
                evidence=f"additionalProperties={ap!r}",
                location=location,
            )
        )

    if risky_name and not required and isinstance(props, dict) and props:
        out.append(
            make_finding(
                "MCPG018",
                description="High-risk tool has no required parameters.",
                evidence=str(schema)[:200],
                location=location,
            )
        )

    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            if not isinstance(prop_schema, dict):
                continue
            prop_loc = location.model_copy(update={"parameter": prop_name})
            ptype = primitive_for(prop_schema)
            lower_name = prop_name.lower()
            risk_kind = HIGH_RISK_PARAM_NAMES.get(lower_name)

            # MCPG022: only fire when the high-risk name lacks ALL constraints
            # (pattern, enum, maxLength). A `filename` with `pattern: "^[A-Za-z0-9_.-]+$"`
            # and `maxLength: 64` is constrained and should not be flagged.
            if risk_kind and ptype == "string":
                max_len, pattern, enum = get_string_constraints(prop_schema)
                if not (pattern or enum or max_len):
                    out.append(
                        make_finding(
                            "MCPG022",
                            description=(
                                f"Parameter `{prop_name}` is a high-risk name "
                                f"({risk_kind}) without pattern/enum/maxLength."
                            ),
                            evidence=str(prop_schema)[:200],
                            location=prop_loc,
                            confidence=0.7,
                        )
                    )
            elif risk_kind and ptype != "string":
                out.append(
                    make_finding(
                        "MCPG022",
                        description=(
                            f"Parameter `{prop_name}` is a high-risk name ({risk_kind})."
                        ),
                        evidence=str(prop_schema)[:200],
                        location=prop_loc,
                        confidence=0.6,
                    )
                )

            if ptype == "string":
                max_len, pattern, enum = get_string_constraints(prop_schema)
                if max_len is None:
                    out.append(
                        make_finding(
                            "MCPG020",
                            description=(
                                f"String parameter `{prop_name}` has no maxLength."
                            ),
                            evidence=str(prop_schema)[:200],
                            location=prop_loc,
                            confidence=0.6,
                        )
                    )
                if risk_kind in {
                    "command-injection",
                    "code-execution",
                    "path-traversal",
                    "ssrf",
                } and not (pattern or enum):
                    out.append(
                        make_finding(
                            "MCPG021",
                            description=(
                                f"High-risk parameter `{prop_name}` has no "
                                "pattern/enum/allowlist."
                            ),
                            evidence=str(prop_schema)[:200],
                            location=prop_loc,
                            confidence=0.85,
                        )
                    )

    # Output schema sanity (very light).
    output_schema = tool.output_schema
    if output_schema is not None and not isinstance(output_schema, dict):
        out.append(
            make_finding(
                "MCPG017",
                description="Output schema is not a JSON object.",
                evidence=str(output_schema)[:200],
                location=location,
            )
        )

    # Recursive walk for nested string params with risky names.
    for path, sub in walk_properties(schema):
        leaf = path[-1].lower()
        if HIGH_RISK_PARAM_NAMES.get(leaf) and primitive_for(sub) == "string":
            max_len, pattern, enum = get_string_constraints(sub)
            if not (pattern or enum):
                out.append(
                    make_finding(
                        "MCPG021",
                        description=(
                            f"Nested parameter `{'.'.join(path)}` has no "
                            "pattern/enum/allowlist."
                        ),
                        evidence=str(sub)[:200],
                        location=location.model_copy(
                            update={"parameter": ".".join(path), "pointer": "/" + "/".join(path)}
                        ),
                        confidence=0.7,
                    )
                )

    return out


def scan_tool(tool: ToolSpec, target: str) -> list[Finding]:
    location = Location(target=target, tool=tool.name)
    out: list[Finding] = []
    out.extend(_description_findings(tool, location))
    out.extend(_name_findings(tool, location))
    out.extend(_annotation_findings(tool, location))
    out.extend(_schema_findings(tool, location))
    return out


def scan_inventory(inventory: Inventory) -> list[Finding]:
    """Run every metadata/schema check against an inspected inventory."""
    out: list[Finding] = []
    target = inventory.target
    if inventory.transport.lower() in {"http", "sse", "streamable-http"}:
        # The config_scan covers binding/auth; if we got here from a live
        # inspect we don't have config context, but we can still nudge.
        out.append(
            make_finding(
                "MCPG008",
                description=(
                    f"Live inspection used the `{inventory.transport}` "
                    "transport; ensure authentication and localhost binding are configured."
                ),
                location=Location(target=target),
                confidence=0.55,
            )
        )
    for tool in inventory.tools:
        out.extend(scan_tool(tool, target))
    return out


def collect_high_risk_tools(inventory: Inventory) -> dict[str, list[str]]:
    """Return ``{tool_name: [risk_kind, ...]}`` for tools whose params look risky."""
    found: dict[str, list[str]] = {}
    for tool in inventory.tools:
        kinds: list[str] = []
        if any(tok in tool.name.lower() for tok in RCE_TOOL_NAME_TOKENS):
            kinds.append("command-injection")
        props = (tool.input_schema or {}).get("properties") if isinstance(tool.input_schema, dict) else None
        if isinstance(props, dict):
            for prop_name in props:
                risk = HIGH_RISK_PARAM_NAMES.get(prop_name.lower())
                if risk and risk not in kinds:
                    kinds.append(risk)
        if kinds:
            found[tool.name] = kinds
    return found
