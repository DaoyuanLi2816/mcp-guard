"""CLI smoke tests via Typer's CliRunner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_guard.cli import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = PROJECT_ROOT / "examples"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_help(runner):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "mcp-guard" in result.stdout
    for cmd in ("scan", "inspect", "fuzz", "sandbox", "report", "init-example"):
        assert cmd in result.stdout


def test_version(runner):
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "mcp-guard" in result.stdout


def test_scan_metadata_example_returns_fail(runner):
    target = EXAMPLES / "vulnerable_metadata_server" / "mcp.json"
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    # FAIL exits with 2.
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "MCPG006" in rule_ids


def test_scan_safe_via_command_returns_pass(runner):
    safe = EXAMPLES / "safe_server" / "server.py"
    cmd = f'"{sys.executable}" "{safe}"'
    result = runner.invoke(
        app,
        ["scan", str(safe), "--command", cmd, "--inspect", "--format", "json"],
    )
    # PASS exits with 0; WARN with 1.
    assert result.exit_code in (0, 1)
    payload = json.loads(result.stdout)
    assert payload["summary"]["verdict"] in {"PASS", "WARN"}


def test_inspect_safe_lists_tools(runner):
    safe = EXAMPLES / "safe_server" / "server.py"
    cmd = f'"{sys.executable}" "{safe}"'
    target = EXAMPLES / "safe_server" / "mcp.json"
    result = runner.invoke(
        app, ["inspect", str(target), "--command", cmd, "--format", "json"]
    )
    assert result.exit_code in (0, 1, 2)
    payload = json.loads(result.stdout)
    inv = payload.get("inventory") or {}
    assert any(t["name"] == "read_allowed_file" for t in inv.get("tools", []))


def test_sandbox_dry_run_produces_strict_flags(runner):
    target = EXAMPLES / "vulnerable_filesystem_server" / "mcp.json"
    result = runner.invoke(
        app, ["sandbox", str(target), "--profile", "strict", "--dry-run"]
    )
    assert result.exit_code == 0
    out = result.stdout
    assert "docker run" in out
    assert "--network" in out and "none" in out
    assert "--read-only" in out
    assert "--cap-drop" in out and "ALL" in out
    assert "no-new-privileges" in out


def test_report_round_trip(tmp_path, runner):
    target = EXAMPLES / "vulnerable_metadata_server" / "mcp.json"
    json_out = tmp_path / "scan.json"
    html_out = tmp_path / "report.html"
    sarif_out = tmp_path / "result.sarif"

    r = runner.invoke(
        app,
        ["scan", str(target), "--format", "json", "--output", str(json_out)],
    )
    assert r.exit_code in (0, 1, 2)
    assert json_out.exists()

    r = runner.invoke(
        app, ["report", str(json_out), "--format", "html", "--output", str(html_out)]
    )
    assert r.exit_code == 0
    assert html_out.exists()
    html_text = html_out.read_text(encoding="utf-8")
    assert "MCPG006" in html_text
    assert "googleapis.com" not in html_text

    r = runner.invoke(
        app, ["report", str(json_out), "--format", "sarif", "--output", str(sarif_out)]
    )
    assert r.exit_code == 0
    payload = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"


def test_fuzz_filesystem_via_command(runner):
    server = EXAMPLES / "vulnerable_filesystem_server" / "server.py"
    cfg = EXAMPLES / "vulnerable_filesystem_server" / "mcp.json"
    result = runner.invoke(
        app,
        [
            "fuzz",
            str(cfg),
            "--command",
            f'"{sys.executable}" "{server}"',
            "--format",
            "json",
        ],
    )
    assert result.exit_code in (1, 2)
    payload = json.loads(result.stdout)
    all_findings = list(payload.get("findings") or [])
    for fr in payload.get("fuzz_results") or []:
        all_findings.extend(fr.get("findings") or [])
    rule_ids = {f["rule_id"] for f in all_findings}
    assert "MCPG025" in rule_ids or "MCPG031" in rule_ids


def test_fuzz_shell_toy_mode(runner):
    server = EXAMPLES / "vulnerable_shell_server" / "server.py"
    cfg = EXAMPLES / "vulnerable_shell_server" / "mcp.json"
    result = runner.invoke(
        app,
        [
            "fuzz",
            str(cfg),
            "--command",
            f'"{sys.executable}" "{server}"',
            "--toy-mode",
            "--format",
            "json",
        ],
    )
    assert result.exit_code in (1, 2)
    payload = json.loads(result.stdout)
    all_findings = list(payload.get("findings") or [])
    for fr in payload.get("fuzz_results") or []:
        all_findings.extend(fr.get("findings") or [])
    rule_ids = {f["rule_id"] for f in all_findings}
    assert "MCPG026" in rule_ids


def test_init_example(tmp_path, runner):
    dest = tmp_path / "my-examples"
    result = runner.invoke(app, ["init-example", str(dest)])
    assert result.exit_code == 0
    assert (dest / "safe_server" / "server.py").exists()
    assert (dest / "vulnerable_metadata_server" / "mcp.json").exists()
