"""SARIF output sanity tests."""

from __future__ import annotations

import json

from mcp_fence.models import Finding, Location, ScanResult, Severity
from mcp_fence.report.sarif import render_sarif


def test_sarif_minimum_shape():
    result = ScanResult(target="x", kind="scan")
    result.findings.append(
        Finding(
            rule_id="MCPG010",
            severity=Severity.HIGH,
            category="tool-metadata",
            title="Prompt injection",
            description="Bad description.",
            recommendation="Fix it.",
            location=Location(path="x.json"),
        )
    )
    result.finalize()
    payload = json.loads(render_sarif(result))
    assert payload["version"] == "2.1.0"
    assert "$schema" in payload
    runs = payload["runs"]
    assert isinstance(runs, list) and runs
    run = runs[0]
    assert run["tool"]["driver"]["name"] == "mcp-fence"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "MCPG010" in rule_ids
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "MCPG010"
    assert res["level"] in {"note", "warning", "error"}
    assert "message" in res and res["message"]["text"]


def test_sarif_empty_result_still_valid():
    result = ScanResult(target="x", kind="scan")
    result.finalize()
    payload = json.loads(render_sarif(result))
    assert payload["runs"][0]["results"] == []
    # Rules array may be empty if there were no findings.
    assert isinstance(payload["runs"][0]["tool"]["driver"]["rules"], list)
