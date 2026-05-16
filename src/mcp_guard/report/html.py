"""Standalone HTML report renderer.

The rendered HTML embeds all CSS inline (no CDN, no remote fonts) so the
file opens offline. Template lives under ``templates/report.html``.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Finding, ScanResult, Severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _severity_key(f: Finding) -> int:
    return _SEVERITY_ORDER.get(f.severity, 9)


def _severity_pct(result: ScanResult) -> dict[str, float]:
    counts = result.summary.by_severity or {}
    total = sum(counts.values()) or 1
    return {k: round(100 * v / total, 1) for k, v in counts.items()}


def _sandbox_hint(result: ScanResult) -> str | None:
    if result.kind != "scan":
        return None
    relevant = any(
        f.category in {"startup-command", "transport-binding", "sandbox"} or f.rule_id == "MCPG023"
        for f in result.findings
    )
    if not relevant:
        return None
    cmd = result.target if result.target.endswith(".json") else "<your mcp.json>"
    return (
        f"mcp-guard sandbox {cmd} --profile strict --dry-run"
    )


def render_html(result: ScanResult) -> str:
    template = _env.get_template("report.html")
    all_findings: list[Finding] = list(result.findings)
    for fr in result.fuzz_results:
        all_findings.extend(fr.findings)
    all_findings.sort(key=_severity_key)
    top = all_findings[:5]
    violations = sum(1 for fr in result.fuzz_results if fr.boundary_violation)
    skipped = sum(1 for fr in result.fuzz_results if fr.skipped)
    remediation: list[Finding] = []
    seen_rule: set[str] = set()
    for f in all_findings:
        if f.rule_id in seen_rule:
            continue
        seen_rule.add(f.rule_id)
        remediation.append(f)

    return template.render(
        result=result,
        all_findings=all_findings,
        top_findings=top,
        severity_pct={
            "critical": _severity_pct(result).get("critical", 0),
            "high": _severity_pct(result).get("high", 0),
            "medium": _severity_pct(result).get("medium", 0),
            "low": _severity_pct(result).get("low", 0),
            "info": _severity_pct(result).get("info", 0),
        },
        violations=violations,
        skipped=skipped,
        remediation=remediation,
        sandbox_hint=_sandbox_hint(result),
    )
