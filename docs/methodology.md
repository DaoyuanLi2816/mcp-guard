# Methodology

This doc describes what `mcp-guard` *actually does* when you run each
command, and why the results look the way they do.

## `scan`

1. Resolves the target.
   - File path → JSON load + `mcpServers` / single-server normalisation.
   - Directory → recursive scan of `.py` files in `code_scan` plus the
     project's `mcp.json` if present.
   - `--command` → ad-hoc shell line; only the startup-command checks
     run unless `--inspect` is passed.
2. `config_scan.scan_config` walks every server and applies
   `MCPG001`–`MCPG009`, `MCPG033`, `MCPG034`.
3. With `--inspect`, the inspector connects via stdio and runs
   `metadata_scan.scan_inventory` against the live tool list. That
   covers `MCPG010`–`MCPG024`.
4. With `--llm-judge` the local LLM is asked to comment on each tool.
5. Findings are aggregated and a single `ScanResult` is rendered as
   `text`/`json`/`sarif`/`html`.

## `inspect`

Live-inspection only. Spawns the MCP server, runs `initialize`,
sends the `notifications/initialized` notification, runs `tools/list`,
and walks the schema. Output is the inventory plus any metadata
findings — equivalent to `scan --inspect` minus the config scan.

## `fuzz`

1. Inspect to obtain the inventory.
2. `fuzz.generator.generate_cases_for_inventory` builds a corpus per
   tool, using the schema to decide where to send each payload class.
3. `fuzz.runner.run_fuzz` reuses one server process. Each case is sent
   as a `tools/call`, with a per-case timeout. Unsafe cases are gated:
   - `--toy-mode` accepts cases when run against the bundled examples.
   - `--allow-unsafe` accepts cases against any server (the safety
     hatch for sandbox use).
   - Default (`safe`) skips command-injection payloads against
     high-risk tools and writes the reason into `skip_reason`.
4. `fuzz.detectors.inspect_fuzz_result` walks each response looking for
   the canonical markers (`MCPG_FUZZ_MARKER_8f2a`, the planted fake
   secret, real-secret patterns, stack traces, absolute paths). Each
   detection becomes a `Finding`.

### Scoring

```
weight(severity): info=0, low=1, medium=4, high=7, critical=10
per-category cap: 25
total score = min(100, Σ capped weights)
verdict:
  any critical or high      → FAIL  (exit 2)
  any medium or low         → WARN  (exit 1)
  otherwise                 → PASS  (exit 0)
```

The per-category cap keeps a single very noisy class (e.g. dozens of
schema warnings) from dominating the score. The cap is intentionally
small so a couple of critical findings always outscore a wall of low
ones.

## `sandbox`

Pure planning: takes the resolved spec and a profile, produces a
`SandboxPlan` containing both an argv list and a single-line `docker
run` invocation. `--dry-run` prints the plan; `--execute` actually
runs it (requires Docker on PATH).

## `report`

Re-renders a previously saved JSON result into any other format.
Useful for archiving JSON and post-hoc generating SARIF / HTML.

## Exit codes

- `0` — PASS / clean
- `1` — WARN
- `2` — FAIL or invocation error
- `3` — sandbox execute requested but Docker not available

## Reproducibility

- The fuzz corpus is deterministic per tool (the case IDs are
  SHA-1-prefixed and stable). Re-running on the same inventory produces
  the same cases.
- Findings carry the rule ID, the rule version-stable
  `default_recommendation`, and an evidence string. Reports diff
  cleanly across versions.
