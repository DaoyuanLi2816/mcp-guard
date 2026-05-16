"""Tests for the schema-driven fuzz generator."""

from __future__ import annotations

from mcp_guard.fuzz.generator import generate_cases_for_tool
from mcp_guard.models import ToolSpec


def _categories(cases) -> set[str]:
    return {c.payload_category for c in cases}


def test_path_traversal_emitted_for_path_param():
    tool = ToolSpec(
        name="read_file",
        description="",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    cases = generate_cases_for_tool(tool)
    cats = _categories(cases)
    assert "path-traversal" in cats
    path_cases = [c for c in cases if c.payload_category == "path-traversal"]
    assert path_cases
    assert all("path" in c.arguments for c in path_cases)
    assert any(".." in c.arguments["path"] for c in path_cases)


def test_command_injection_emitted_for_command_param():
    tool = ToolSpec(
        name="run_command",
        description="",
        input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    )
    cases = generate_cases_for_tool(tool)
    assert "command-injection" in _categories(cases)
    # All command injection payloads should be unsafe-flagged and contain marker.
    inj = [c for c in cases if c.payload_category == "command-injection"]
    assert inj
    assert all(c.is_unsafe for c in inj)


def test_ssrf_emitted_for_url_param():
    tool = ToolSpec(
        name="fetch",
        description="",
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    )
    cases = generate_cases_for_tool(tool)
    assert "ssrf" in _categories(cases)


def test_oversize_input_emitted():
    tool = ToolSpec(
        name="summarize",
        description="",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    )
    cases = generate_cases_for_tool(tool)
    assert "oversize-input" in _categories(cases)
    oversize = [c for c in cases if c.payload_category == "oversize-input"]
    assert any(len(c.arguments.get("text", "")) > 1000 for c in oversize)


def test_extra_property_and_missing_required():
    tool = ToolSpec(
        name="op",
        description="",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
            "required": ["a"],
        },
    )
    cases = generate_cases_for_tool(tool)
    cats = _categories(cases)
    assert "extra-property" in cats
    assert "missing-required" in cats


def test_extra_traversal_targets_included():
    tool = ToolSpec(
        name="read_file",
        description="",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    cases = generate_cases_for_tool(
        tool, extra_traversal_targets=["/abs/path/to/secret.txt"]
    )
    assert any(
        c.arguments.get("path") == "/abs/path/to/secret.txt"
        for c in cases
        if c.payload_category == "path-traversal"
    )
