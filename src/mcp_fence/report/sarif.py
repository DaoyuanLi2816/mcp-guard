"""SARIF 2.1.0 renderer."""

from __future__ import annotations

import json
from typing import Any

from ..constants import RULE_CATALOG
from ..models import Finding, ScanResult

_SARIF_VERSION = "2.1.0"
_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def _used_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        spec = RULE_CATALOG.get(f.rule_id)
        if not spec:
            continue
        seen[f.rule_id] = {
            "id": f.rule_id,
            "name": spec["title"],
            "shortDescription": {"text": spec["title"]},
            "fullDescription": {"text": spec["rationale"]},
            "helpUri": "https://github.com/mcp-fence/mcp-fence/blob/main/docs/rule_catalog.md",
            "defaultConfiguration": {"level": f.severity.sarif_level},
            "properties": {
                "category": spec["category"],
                "severity": spec["severity"].value,
                "recommendation": spec["recommendation"],
            },
        }
    return list(seen.values())


def _location_for_finding(f: Finding, target: str) -> dict[str, Any]:
    uri = f.location.path or target or "in-memory"
    physical: dict[str, Any] = {"artifactLocation": {"uri": str(uri)}}
    if f.location.line:
        physical["region"] = {"startLine": int(f.location.line)}
    logical: list[dict[str, Any]] = []
    if f.location.tool:
        logical.append({"name": f.location.tool, "kind": "tool"})
    if f.location.parameter:
        logical.append({"name": f.location.parameter, "kind": "parameter"})
    loc: dict[str, Any] = {"physicalLocation": physical}
    if logical:
        loc["logicalLocations"] = logical
    return loc


def render_sarif(result: ScanResult) -> str:
    all_findings: list[Finding] = list(result.findings)
    for fr in result.fuzz_results:
        all_findings.extend(fr.findings)

    rules = _used_rules(all_findings)

    sarif_results: list[dict[str, Any]] = []
    for f in all_findings:
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f.description},
                "locations": [_location_for_finding(f, result.target)],
                "properties": {
                    "category": f.category,
                    "confidence": f.confidence,
                    "source": f.source,
                    "evidence": (f.evidence or "")[:1024],
                    "recommendation": f.recommendation,
                },
            }
        )

    payload: dict[str, Any] = {
        "version": _SARIF_VERSION,
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-fence",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/mcp-fence/mcp-fence",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.started_at,
                        "endTimeUtc": result.completed_at or result.started_at,
                    }
                ],
                "properties": {
                    "summary": result.summary.model_dump(),
                    "target": result.target,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
