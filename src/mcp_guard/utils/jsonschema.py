"""Small helpers for walking a JSON Schema without pulling in jsonschema.

Only the subset that mcp-guard needs is supported:

- ``type``
- ``properties`` / ``required`` / ``additionalProperties``
- ``items``
- ``enum`` / ``pattern`` / ``maxLength`` / ``minLength``
- nested objects / arrays
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def walk_properties(
    schema: dict[str, Any], path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    """Yield (path, property_schema) for every leaf property in *schema*."""
    if not isinstance(schema, dict):
        return
    schema_type = schema.get("type")
    if schema_type == "object" or "properties" in schema:
        for name, sub in (schema.get("properties") or {}).items():
            if isinstance(sub, dict):
                yield from walk_properties(sub, (*path, name))
        return
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            yield from walk_properties(items, (*path, "[]"))
        return
    if path:
        yield (path, schema)


def is_object_schema(schema: dict[str, Any] | None) -> bool:
    if not isinstance(schema, dict):
        return False
    return schema.get("type") == "object" or "properties" in schema


def required_set(schema: dict[str, Any]) -> set[str]:
    req = schema.get("required") or []
    return set(req) if isinstance(req, list) else set()


def get_string_constraints(schema: dict[str, Any]) -> tuple[int | None, str | None, list[Any] | None]:
    """Return (maxLength, pattern, enum) for a string-typed schema."""
    return (
        schema.get("maxLength") if isinstance(schema.get("maxLength"), int) else None,
        schema.get("pattern") if isinstance(schema.get("pattern"), str) else None,
        schema.get("enum") if isinstance(schema.get("enum"), list) else None,
    )


def primitive_for(schema: dict[str, Any]) -> str:
    """Best-effort primitive type for a JSON schema node."""
    t = schema.get("type")
    if isinstance(t, list):
        for cand in ("string", "integer", "number", "boolean", "object", "array"):
            if cand in t:
                return cand
        return t[0] if t else "string"
    if isinstance(t, str):
        return t
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        first = schema["enum"][0]
        if isinstance(first, bool):
            return "boolean"
        if isinstance(first, int):
            return "integer"
        if isinstance(first, float):
            return "number"
        if isinstance(first, str):
            return "string"
        if isinstance(first, list):
            return "array"
        if isinstance(first, dict):
            return "object"
    return "string"
