"""mcp-guard command-line interface."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import typer

from . import __version__
from .fuzz import RunMode, generate_cases_for_inventory, run_fuzz
from .fuzz.detectors import attach_findings
from .llm.local_judge import judge_inventory
from .mcp.inventory import ServerSpec, _split_cmdline, inspect_target, resolve_specs_from_target
from .models import ScanResult
from .report.html import render_html
from .report.sarif import render_sarif
from .report.text import render_text
from .sandbox.docker import build_plan
from .sandbox.profiles import PROFILES
from .scanner.code_scan import scan_directory
from .scanner.config_scan import scan_ad_hoc_command, scan_config_file
from .scanner.metadata_scan import scan_inventory
from .utils.logging import configure as configure_logging
from .utils.paths import write_text

app = typer.Typer(
    name="mcp-guard",
    help="Local-first security scanner / inspector / fuzzer / sandbox for MCP servers.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-guard {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    debug: bool = typer.Option(False, "--debug", help="Enable verbose logging."),
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Print version and exit."
    ),
) -> None:
    configure_logging(debug=debug)


# ---------- helpers ----------

def _emit_result(
    result: ScanResult,
    fmt: str,
    output: Path | None,
) -> int:
    result.finalize()
    rendered = _render(result, fmt)
    if output:
        write_text(output, rendered)
        typer.echo(f"wrote {fmt} report to {output}")
    else:
        typer.echo(rendered)
    s = result.summary
    if s.verdict == "FAIL":
        return 2
    if s.verdict == "WARN":
        return 1
    return 0


def _render(result: ScanResult, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return result.model_dump_json(indent=2)
    if fmt == "text":
        return render_text(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "html":
        return render_html(result)
    raise typer.BadParameter(f"unknown format: {fmt}")


def _resolve_specs(
    target: str,
    command_override: str | None,
) -> list[ServerSpec]:
    return resolve_specs_from_target(target, command_override=command_override)


def _shorten_target_for_result(target: str, command_override: str | None) -> str:
    if command_override:
        return f"command:{command_override}"
    return target


def _try_load_existing_scan(path: Path) -> ScanResult:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ScanResult.model_validate(raw)


# ---------- scan ----------


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Path to mcp.json, a directory of source, or `--command \"…\"` form.",
    ),
    command: str | None = typer.Option(
        None,
        "--command",
        help="Treat the argument as an ad-hoc start command (skips config file load).",
    ),
    format: str = typer.Option("text", "--format", "-f", help="text | json | sarif | html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to PATH."),
    inspect_live: bool = typer.Option(
        False,
        "--inspect/--no-inspect",
        help="Also live-inspect the server to scan tool metadata and schemas.",
    ),
    llm_judge: str | None = typer.Option(
        None,
        "--llm-judge",
        help="Optional local LLM judge: 'ollama' or 'openai-compatible'.",
    ),
    llm_endpoint: str | None = typer.Option(
        None, "--llm-endpoint", help="Override the local LLM endpoint URL."
    ),
    llm_model: str | None = typer.Option(None, "--llm-model", help="Local LLM model name."),
) -> None:
    """Static scan a config / project / command."""
    result = ScanResult(
        target=_shorten_target_for_result(target, command),
        kind="scan",
        tool_version=__version__,
    )

    # ----- direct command line -----
    if command is not None:
        result.findings.extend(scan_ad_hoc_command(command))
        if inspect_live or llm_judge:
            spec = ServerSpec(
                name="cli-command",
                transport="stdio",
                argv=_split_cmdline(command),
                source=f"command:{command}",
            )
            inv, inv_findings = inspect_target(spec)
            result.inventory = inv
            result.findings.extend(inv_findings)
            result.findings.extend(scan_inventory(inv))
            if llm_judge:
                result.findings.extend(
                    judge_inventory(
                        inv,
                        backend=llm_judge,
                        endpoint=llm_endpoint,
                        model=llm_model,
                    )
                )
        sys.exit(_emit_result(result, format, output))

    # ----- config file -----
    p = Path(target)
    if p.is_file():
        try:
            result.findings.extend(scan_config_file(p))
        except ValueError as e:
            typer.echo(f"error: {e}", err=True)
            sys.exit(2)
        if inspect_live or llm_judge:
            specs = _resolve_specs(target, command)
            for spec in specs[:1]:
                if spec.transport != "stdio" or not spec.argv:
                    result.notes.append(
                        f"Live inspection unavailable for transport `{spec.transport}` "
                        "in v0.1; static checks only."
                    )
                    continue
                inv, inv_findings = inspect_target(spec)
                result.inventory = inv
                result.findings.extend(inv_findings)
                result.findings.extend(scan_inventory(inv))
                if llm_judge:
                    result.findings.extend(
                        judge_inventory(
                            inv,
                            backend=llm_judge,
                            endpoint=llm_endpoint,
                            model=llm_model,
                        )
                    )
        sys.exit(_emit_result(result, format, output))

    # ----- directory -----
    if p.is_dir():
        result.findings.extend(scan_directory(p))
        candidate = p / "mcp.json"
        if candidate.exists():
            result.findings.extend(scan_config_file(candidate))
        sys.exit(_emit_result(result, format, output))

    typer.echo(f"error: target not found: {target}", err=True)
    sys.exit(2)


# ---------- inspect ----------


@app.command()
def inspect(
    target: str = typer.Argument(..., help="Path to mcp.json or use --command."),
    command: str | None = typer.Option(None, "--command", help="Ad-hoc start command."),
    format: str = typer.Option("text", "--format", "-f", help="text | json | sarif | html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to PATH."),
    timeout: float = typer.Option(10.0, "--timeout", help="Initialize/tools-list timeout (sec)."),
) -> None:
    """Live-inspect an MCP server over stdio and report its inventory."""
    specs = _resolve_specs(target, command)
    if not specs:
        typer.echo(f"error: no server found in {target}", err=True)
        sys.exit(2)

    result = ScanResult(
        target=_shorten_target_for_result(target, command),
        kind="inspect",
        tool_version=__version__,
    )
    spec = specs[0]
    inv, inv_findings = inspect_target(spec, timeout=timeout)
    result.inventory = inv
    result.findings.extend(inv_findings)
    # Inspect runs the metadata scan too — that's the value of `inspect`.
    result.findings.extend(scan_inventory(inv))
    sys.exit(_emit_result(result, format, output))


# ---------- fuzz ----------


@app.command()
def fuzz(
    target: str = typer.Argument(..., help="Path to mcp.json or use --command."),
    command: str | None = typer.Option(None, "--command", help="Ad-hoc start command."),
    format: str = typer.Option("text", "--format", "-f", help="text | json | sarif | html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to PATH."),
    timeout: float = typer.Option(8.0, "--timeout", help="Per-call timeout (sec)."),
    max_cases: int | None = typer.Option(None, "--max-cases", help="Hard cap on cases."),
    toy_mode: bool = typer.Option(
        False, "--toy-mode", help="Allow running unsafe payloads against bundled examples."
    ),
    allow_unsafe: bool = typer.Option(
        False,
        "--allow-unsafe",
        help="Run unsafe payloads against the live server. ONLY in a sandbox.",
    ),
    traversal_target: str | None = typer.Option(
        None,
        "--traversal-target",
        help="Filename to aim path-traversal payloads at (defaults to fake_secret.txt).",
    ),
) -> None:
    """Dynamic schema-driven fuzzer."""
    specs = _resolve_specs(target, command)
    if not specs:
        typer.echo(f"error: no server found in {target}", err=True)
        sys.exit(2)

    spec = specs[0]
    inv, inv_findings = inspect_target(spec, timeout=timeout)
    if not inv.tools:
        typer.echo("warning: no tools enumerated; nothing to fuzz", err=True)

    extra_targets: list[str] = []
    # If the server's script directory contains a fake_secret.txt (the toy
    # examples ship one), aim a payload directly at it so the detector fires
    # even when the server's cwd differs from the script dir.
    if spec.argv:
        for tok in spec.argv:
            candidate_path = Path(tok)
            try:
                if candidate_path.is_file():
                    secret = candidate_path.resolve().parent / (traversal_target or "fake_secret.txt")
                    if secret.exists():
                        extra_targets.append(str(secret))
            except OSError:
                pass
    cases = generate_cases_for_inventory(
        inv,
        traversal_targets_filename=traversal_target,
        extra_traversal_targets=extra_targets or None,
    )
    mode = RunMode.SAFE
    if allow_unsafe:
        mode = RunMode.ALLOW_UNSAFE
    elif toy_mode:
        mode = RunMode.TOY

    results = run_fuzz(
        spec,
        inv,
        cases,
        mode=mode,
        call_timeout=timeout,
        max_cases=max_cases,
    )
    attach_findings(results)

    result = ScanResult(
        target=_shorten_target_for_result(target, command),
        kind="fuzz",
        tool_version=__version__,
        inventory=inv,
        findings=list(inv_findings),
        fuzz_results=results,
    )
    sys.exit(_emit_result(result, format, output))


# ---------- sandbox ----------


@app.command()
def sandbox(
    target: str = typer.Argument(..., help="Path to mcp.json or use --command."),
    command: str | None = typer.Option(None, "--command", help="Ad-hoc start command."),
    profile: str = typer.Option(
        "strict",
        "--profile",
        help=f"Sandbox profile: {', '.join(PROFILES)}.",
    ),
    image: str = typer.Option("python:3.12-slim", "--image", help="Base Docker image."),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="Print or actually run."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write plan to PATH."),
) -> None:
    """Generate (and optionally execute) a Docker sandbox command."""
    specs = _resolve_specs(target, command)
    if not specs:
        typer.echo(f"error: no server found in {target}", err=True)
        sys.exit(2)
    spec = specs[0]
    if spec.transport != "stdio" or not spec.argv:
        typer.echo(
            f"error: sandbox in v0.1 supports stdio servers only (got {spec.transport!r}).",
            err=True,
        )
        sys.exit(2)

    plan = build_plan(spec, profile_name=profile, image=image)
    payload = {
        "target": plan.target,
        "profile": plan.profile,
        "image": plan.image,
        "docker_command": plan.docker_command,
        "docker_argv": plan.docker_argv,
        "compose_fragment": plan.compose_fragment,
        "notes": plan.notes,
        "docker_available": plan.docker_available,
    }
    rendered = json.dumps(payload, indent=2)

    if output:
        write_text(output, rendered)
        typer.echo(f"wrote sandbox plan to {output}")
    else:
        typer.echo(rendered)

    if dry_run:
        typer.echo("\n# To run this sandbox:")
        typer.echo(plan.docker_command)
        sys.exit(0)

    if not plan.docker_available:
        typer.echo(
            "Docker is not installed on this host. Either install Docker "
            "(https://docs.docker.com/engine/install/) or rerun with --dry-run.",
            err=True,
        )
        sys.exit(3)
    from .sandbox.docker import execute_plan  # local import to avoid noise in dry-run path

    completed = execute_plan(plan, timeout=120.0)
    typer.echo(completed.stdout or "")
    if completed.returncode != 0:
        typer.echo(completed.stderr or "", err=True)
        sys.exit(completed.returncode)


# ---------- report ----------


@app.command()
def report(
    input_path: Path = typer.Argument(..., help="Path to a previous mcp-guard JSON result."),
    format: str = typer.Option("html", "--format", "-f", help="html | text | sarif | json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to PATH."),
) -> None:
    """Render a previously saved JSON result into another format."""
    if not input_path.exists():
        typer.echo(f"error: file not found: {input_path}", err=True)
        sys.exit(2)
    try:
        result = _try_load_existing_scan(input_path)
    except Exception as e:
        typer.echo(f"error: could not parse {input_path}: {e}", err=True)
        sys.exit(2)
    result.compute_summary()
    rendered = _render(result, format)
    if output:
        write_text(output, rendered)
        typer.echo(f"wrote {format} report to {output}")
    else:
        typer.echo(rendered)


# ---------- init-example ----------


@app.command("init-example")
def init_example(
    destination: Path = typer.Argument(
        Path("./mcp-guard-examples"),
        help="Where to copy the bundled examples.",
    ),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite an existing directory."),
) -> None:
    """Copy the bundled example servers into a working directory."""
    pkg_examples = Path(__file__).resolve().parent.parent.parent / "examples"
    if not pkg_examples.exists():
        # Falls back to the cwd's examples/ during local development.
        pkg_examples = Path.cwd() / "examples"
    if not pkg_examples.exists():
        typer.echo("error: bundled examples not found.", err=True)
        sys.exit(2)
    if destination.exists():
        if not overwrite:
            typer.echo(
                f"error: {destination} already exists. Pass --overwrite to replace it.",
                err=True,
            )
            sys.exit(2)
        shutil.rmtree(destination)
    shutil.copytree(pkg_examples, destination)
    typer.echo(f"copied examples to {destination}")
    typer.echo(
        "\nTry:\n"
        f"  mcp-guard scan {destination}/vulnerable_metadata_server/mcp.json\n"
        f"  mcp-guard inspect {destination}/safe_server/mcp.json\n"
        f"  mcp-guard fuzz {destination}/vulnerable_filesystem_server/mcp.json"
    )


def main() -> None:  # for ``python -m mcp_guard``
    app()


__all__ = ["app", "main"]
