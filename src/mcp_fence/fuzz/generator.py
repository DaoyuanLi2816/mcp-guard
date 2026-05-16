"""Translate a tool's JSON Schema into a corpus of :class:`FuzzCase`."""

from __future__ import annotations

import hashlib
from typing import Any

from ..constants import HIGH_RISK_PARAM_NAMES, RCE_TOOL_NAME_TOKENS
from ..models import FuzzCase, Inventory, ToolSpec
from ..utils.jsonschema import primitive_for
from . import payloads as P


def _case_id(tool_name: str, category: str, idx: int, payload: object) -> str:
    h = hashlib.sha1(f"{tool_name}|{category}|{idx}|{payload!r}".encode()).hexdigest()[:8]
    return f"{tool_name}:{category}:{h}"


def _example_value(schema: dict[str, Any]) -> Any:
    """Return a plausible value for *schema* so we can build base arguments."""
    if not isinstance(schema, dict):
        return ""
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return schema["enum"][0]
    t = primitive_for(schema)
    if t == "string":
        if "pattern" in schema:
            return "ok"
        return "example"
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "array":
        items = schema.get("items") if isinstance(schema, dict) else None
        if isinstance(items, dict):
            return [_example_value(items)]
        return []
    if t == "object":
        out: dict[str, Any] = {}
        for k, sub in (schema.get("properties") or {}).items():
            if isinstance(sub, dict):
                out[k] = _example_value(sub)
        return out
    return ""


def _baseline_arguments(input_schema: dict[str, Any]) -> dict[str, Any]:
    """Produce a baseline arguments dict that satisfies *required*."""
    args: dict[str, Any] = {}
    props = input_schema.get("properties") if isinstance(input_schema, dict) else None
    required = set(input_schema.get("required") or []) if isinstance(input_schema, dict) else set()
    if isinstance(props, dict):
        for name, sub in props.items():
            if name in required and isinstance(sub, dict):
                args[name] = _example_value(sub)
    return args


def _string_props(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    out: list[tuple[str, dict[str, Any]]] = []
    if not isinstance(props, dict):
        return out
    for name, sub in props.items():
        if not isinstance(sub, dict):
            continue
        if primitive_for(sub) == "string":
            out.append((name, sub))
    return out


def _is_path_param(name: str) -> bool:
    return HIGH_RISK_PARAM_NAMES.get(name.lower()) == "path-traversal" or name.lower() in {
        "path", "filepath", "file_path", "filename", "directory", "file",
    }


def _is_command_param(name: str) -> bool:
    return HIGH_RISK_PARAM_NAMES.get(name.lower()) in {"command-injection", "code-execution"} or (
        name.lower() in {"command", "cmd", "shell", "exec", "code", "eval", "script"}
    )


def _is_url_param(name: str) -> bool:
    return HIGH_RISK_PARAM_NAMES.get(name.lower()) == "ssrf" or name.lower() in {
        "url", "endpoint", "webhook", "callback", "href", "link",
    }


def _is_freeform_text(name: str, schema: dict[str, Any]) -> bool:
    if _is_path_param(name) or _is_command_param(name) or _is_url_param(name):
        return False
    if "enum" in schema:
        return False
    return True


def _tool_is_rce_like(tool: ToolSpec) -> bool:
    return any(tok in tool.name.lower() for tok in RCE_TOOL_NAME_TOKENS)


def generate_cases_for_tool(
    tool: ToolSpec,
    *,
    traversal_targets_filename: str | None = None,
    extra_traversal_targets: list[str] | None = None,
) -> list[FuzzCase]:
    cases: list[FuzzCase] = []
    schema = tool.input_schema or {}
    base = _baseline_arguments(schema)
    string_props = _string_props(schema)

    # 1) Path traversal — every path-like string param.
    path_targets = P.traversal_targets(traversal_targets_filename)
    if extra_traversal_targets:
        path_targets = list(path_targets) + list(extra_traversal_targets)
    path_param_names = [n for (n, _) in string_props if _is_path_param(n)]
    for prop_name in path_param_names:
        for idx, payload in enumerate(path_targets):
            args = dict(base)
            args[prop_name] = payload
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"path-traversal:{prop_name}", idx, payload),
                    tool_name=tool.name,
                    payload_category="path-traversal",
                    intent=f"path traversal on `{prop_name}`",
                    arguments=args,
                    is_unsafe=False,
                )
            )

    # 2) Command injection — only against commandy params.
    command_param_names = [n for (n, _) in string_props if _is_command_param(n)]
    if not command_param_names and _tool_is_rce_like(tool):
        # No obvious commandy param but the tool name implies RCE — target
        # the first string param.
        if string_props:
            command_param_names = [string_props[0][0]]
    for prop_name in command_param_names:
        for idx, payload in enumerate(P.COMMAND_INJECTION):
            args = dict(base)
            args[prop_name] = payload
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"command-injection:{prop_name}", idx, payload),
                    tool_name=tool.name,
                    payload_category="command-injection",
                    intent=f"command injection on `{prop_name}`",
                    arguments=args,
                    is_unsafe=True,
                )
            )

    # 3) SSRF.
    url_param_names = [n for (n, _) in string_props if _is_url_param(n)]
    for prop_name in url_param_names:
        for idx, payload in enumerate(P.SSRF_URLS):
            args = dict(base)
            args[prop_name] = payload
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"ssrf:{prop_name}", idx, payload),
                    tool_name=tool.name,
                    payload_category="ssrf",
                    intent=f"SSRF on `{prop_name}`",
                    arguments=args,
                    is_unsafe=False,
                )
            )

    # 4) Prompt injection — any freeform text-ish param.
    freeform_names = [n for (n, s) in string_props if _is_freeform_text(n, s)]
    target_text_param = freeform_names[0] if freeform_names else None
    if target_text_param:
        for idx, payload in enumerate(P.PROMPT_INJECTION_TEXTS):
            args = dict(base)
            args[target_text_param] = payload
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"prompt-injection:{target_text_param}", idx, payload),
                    tool_name=tool.name,
                    payload_category="prompt-injection",
                    intent=f"prompt-injection on `{target_text_param}`",
                    arguments=args,
                    is_unsafe=False,
                )
            )

    # 5) Oversize input — first string param.
    if string_props:
        prop_name, prop_schema = string_props[0]
        target_len = 100_000
        max_len = prop_schema.get("maxLength")
        if isinstance(max_len, int) and max_len > 0:
            target_len = max(max_len * 2, 1024)
        target_len = min(target_len, 200_000)
        args = dict(base)
        args[prop_name] = P.oversize_payload(target_len)
        cases.append(
            FuzzCase(
                case_id=_case_id(tool.name, f"oversize:{prop_name}", 0, target_len),
                tool_name=tool.name,
                payload_category="oversize-input",
                intent=f"oversize string on `{prop_name}`",
                arguments=args,
            )
        )

    # 6) Type confusion — for each property in required set.
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        for idx, (name, sub) in enumerate(props.items()):
            if not isinstance(sub, dict):
                continue
            declared = primitive_for(sub)
            wrong = P.type_confusion_value(declared)
            if wrong is None:
                continue
            args = dict(base)
            args[name] = wrong
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"type-confusion:{name}", idx, wrong),
                    tool_name=tool.name,
                    payload_category="type-confusion",
                    intent=f"wrong-type {declared!r} for `{name}`",
                    arguments=args,
                )
            )

    # 7) Missing required.
    required = list(schema.get("required") or []) if isinstance(schema, dict) else []
    for r in required:
        args = dict(base)
        args.pop(r, None)
        cases.append(
            FuzzCase(
                case_id=_case_id(tool.name, f"missing-required:{r}", 0, r),
                tool_name=tool.name,
                payload_category="missing-required",
                intent=f"omit required `{r}`",
                arguments=args,
            )
        )

    # 8) Extra property.
    args = dict(base)
    args["mcp_fence_unexpected_field"] = "shouldNotBeAllowed"
    cases.append(
        FuzzCase(
            case_id=_case_id(tool.name, "extra-property", 0, "unexpected"),
            tool_name=tool.name,
            payload_category="extra-property",
            intent="extra unexpected property",
            arguments=args,
        )
    )

    # 9) Env / secret probes against the most-likely text param.
    if target_text_param:
        for idx, payload in enumerate(P.ENV_PROBES):
            args = dict(base)
            args[target_text_param] = payload
            cases.append(
                FuzzCase(
                    case_id=_case_id(tool.name, f"env-probe:{target_text_param}", idx, payload),
                    tool_name=tool.name,
                    payload_category="env-probe",
                    intent=f"env probe on `{target_text_param}`",
                    arguments=args,
                )
            )

    return cases


def generate_cases_for_inventory(
    inventory: Inventory,
    *,
    traversal_targets_filename: str | None = None,
    extra_traversal_targets: list[str] | None = None,
) -> list[FuzzCase]:
    out: list[FuzzCase] = []
    for tool in inventory.tools:
        out.extend(
            generate_cases_for_tool(
                tool,
                traversal_targets_filename=traversal_targets_filename,
                extra_traversal_targets=extra_traversal_targets,
            )
        )
    return out
