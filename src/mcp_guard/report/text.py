"""Plaintext / table renderer for the CLI."""

from __future__ import annotations

from io import StringIO

from ..models import Finding, ScanResult, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _severity_key(f: Finding) -> int:
    return _SEVERITY_ORDER.get(f.severity, 9)


def _trim(s: str | None, n: int) -> str:
    if not s:
        return ""
    s = " ".join(s.split())
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "  (no findings)\n"
    rows: list[tuple[str, str, str, str, str, str]] = []
    for f in sorted(findings, key=_severity_key):
        rows.append(
            (
                f.severity.value.upper(),
                f.rule_id,
                _trim(f.title, 40),
                _trim(f.category, 22),
                _trim(f.location.short(), 36),
                _trim(f.description, 56),
            )
        )
    headers = ("SEV", "RULE", "TITLE", "CATEGORY", "WHERE", "DETAIL")
    widths = [
        max(len(headers[i]), max((len(r[i]) for r in rows), default=0))
        for i in range(len(headers))
    ]
    out = StringIO()
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    out.write(fmt.format(*headers) + "\n")
    out.write("  " + "  ".join("-" * w for w in widths) + "\n")
    for r in rows:
        out.write(fmt.format(*r) + "\n")
    return out.getvalue()


def render_text(result: ScanResult) -> str:
    out = StringIO()
    out.write(f"mcp-guard {result.tool_version} :: {result.kind} :: target={result.target}\n")
    if result.inventory is not None:
        inv = result.inventory
        out.write(
            f"  transport={inv.transport} tools={len(inv.tools)} "
            f"server={inv.server_info.name or '?'}\n"
        )
        if inv.warnings:
            out.write("  warnings:\n")
            for w in inv.warnings[:10]:
                out.write(f"    - {_trim(w, 100)}\n")

    if result.fuzz_results:
        by_skipped = sum(1 for r in result.fuzz_results if r.skipped)
        by_violation = sum(1 for r in result.fuzz_results if r.boundary_violation)
        out.write(
            f"  fuzz: cases={len(result.fuzz_results)} "
            f"skipped={by_skipped} boundary_violations={by_violation}\n"
        )

    s = result.summary
    out.write(
        f"  summary: total={s.total} score={s.score}/100 verdict={s.verdict}\n"
    )
    if s.by_severity:
        parts = [f"{k}={v}" for k, v in sorted(s.by_severity.items())]
        out.write("  by_severity: " + ", ".join(parts) + "\n")
    if s.by_category:
        parts = [f"{k}={v}" for k, v in sorted(s.by_category.items())]
        out.write("  by_category: " + ", ".join(parts) + "\n")

    all_findings: list[Finding] = list(result.findings)
    for fr in result.fuzz_results:
        all_findings.extend(fr.findings)

    out.write("\n# Findings\n")
    out.write(_findings_table(all_findings))

    if all_findings:
        out.write("\n# Top 5 by severity\n")
        top = sorted(all_findings, key=_severity_key)[:5]
        for i, f in enumerate(top, 1):
            out.write(
                f"  {i}. [{f.severity.value.upper()}] {f.rule_id} {f.title}\n"
                f"      where: {f.location.short()}\n"
                f"      why:   {_trim(f.description, 200)}\n"
                f"      fix:   {_trim(f.recommendation, 200)}\n"
            )
    return out.getvalue()
