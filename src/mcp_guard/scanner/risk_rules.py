"""Shared helpers for turning a rule lookup into a Finding."""

from __future__ import annotations

from ..constants import rule
from ..models import Finding, Location, Severity


def make_finding(
    rule_id: str,
    *,
    description: str,
    evidence: str | None = None,
    recommendation: str | None = None,
    location: Location | None = None,
    confidence: float = 0.85,
    source: str = "static",
    severity_override: Severity | None = None,
) -> Finding:
    spec = rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=severity_override or spec["severity"],
        category=spec["category"],
        title=spec["title"],
        description=description,
        evidence=evidence,
        recommendation=recommendation or spec["recommendation"],
        confidence=max(0.0, min(1.0, confidence)),
        location=location or Location(),
        source=source,
    )
