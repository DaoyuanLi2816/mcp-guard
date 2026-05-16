"""End-to-end tests that exercise the bundled example servers.

These tests launch each toy MCP server as a stdio child via the real
mcp-fence inspector/fuzzer to cover the full pipeline.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mcp_fence.fuzz import RunMode, generate_cases_for_inventory, run_fuzz
from mcp_fence.fuzz.detectors import attach_findings
from mcp_fence.mcp.inventory import ServerSpec, inspect_target
from mcp_fence.scanner.config_scan import scan_config_file
from mcp_fence.scanner.metadata_scan import scan_inventory

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAFE = EXAMPLES / "safe_server" / "server.py"
VULN_FS = EXAMPLES / "vulnerable_filesystem_server" / "server.py"
VULN_SHELL = EXAMPLES / "vulnerable_shell_server" / "server.py"
VULN_META = EXAMPLES / "vulnerable_metadata_server" / "server.py"


def _spec(script: Path, name: str = "test") -> ServerSpec:
    return ServerSpec(
        name=name,
        transport="stdio",
        argv=[sys.executable, str(script)],
        source=str(script),
    )


def test_safe_server_inspect_lists_tools():
    inv, findings = inspect_target(_spec(SAFE, "safe"))
    assert len(inv.tools) >= 1
    tool_names = {t.name for t in inv.tools}
    assert "read_allowed_file" in tool_names
    # The safe server's metadata should produce no findings.
    inv_findings = scan_inventory(inv)
    inv_findings = [f for f in inv_findings if f.severity.value in {"high", "critical", "medium"}]
    assert inv_findings == []
    assert findings == []  # no protocol errors


def test_vulnerable_metadata_server_static_scan_catches_prompt_injection():
    inv, _ = inspect_target(_spec(VULN_META, "vuln-meta"))
    findings = scan_inventory(inv)
    rule_ids = {f.rule_id for f in findings}
    assert "MCPG010" in rule_ids
    assert "MCPG011" in rule_ids
    assert "MCPG012" in rule_ids
    assert "MCPG013" in rule_ids


def test_vulnerable_filesystem_fuzz_detects_path_traversal(tmp_path):
    inv, _ = inspect_target(_spec(VULN_FS, "vuln-fs"))
    spec = _spec(VULN_FS, "vuln-fs")
    secret_path = VULN_FS.parent / "fake_secret.txt"
    cases = generate_cases_for_inventory(
        inv,
        extra_traversal_targets=[str(secret_path)],
    )
    results = run_fuzz(spec, inv, cases, mode=RunMode.SAFE, call_timeout=5.0)
    attach_findings(results)
    all_findings = [f for r in results for f in r.findings]
    rule_ids = {f.rule_id for f in all_findings}
    assert "MCPG025" in rule_ids or "MCPG031" in rule_ids
    # At least one boundary violation should fire.
    assert any(r.boundary_violation for r in results)


def test_vulnerable_shell_fuzz_toy_mode_detects_marker():
    inv, _ = inspect_target(_spec(VULN_SHELL, "vuln-shell"))
    spec = _spec(VULN_SHELL, "vuln-shell")
    cases = generate_cases_for_inventory(inv)
    results = run_fuzz(spec, inv, cases, mode=RunMode.TOY, call_timeout=6.0)
    attach_findings(results)
    rule_ids = {f.rule_id for r in results for f in r.findings}
    assert "MCPG026" in rule_ids


def test_vulnerable_shell_fuzz_safe_mode_skips_command_injection():
    inv, _ = inspect_target(_spec(VULN_SHELL, "vuln-shell"))
    spec = _spec(VULN_SHELL, "vuln-shell")
    cases = generate_cases_for_inventory(inv)
    results = run_fuzz(spec, inv, cases, mode=RunMode.SAFE, call_timeout=5.0)
    attach_findings(results)
    skipped = [r for r in results if r.skipped]
    assert any("safe-mode" in (r.skip_reason or "") for r in skipped)
    # And no MCPG026 should fire because we never executed those payloads.
    rule_ids = {f.rule_id for r in results for f in r.findings}
    assert "MCPG026" not in rule_ids


def test_vulnerable_http_config_static_scan():
    config_path = EXAMPLES / "vulnerable_http_server" / "mcp.json"
    findings = scan_config_file(config_path)
    rule_ids = {f.rule_id for f in findings}
    # bind 0.0.0.0, no auth, env secret, broad allowlist
    assert "MCPG007" in rule_ids
    assert "MCPG008" in rule_ids
    assert "MCPG009" in rule_ids
    assert "MCPG006" in rule_ids
