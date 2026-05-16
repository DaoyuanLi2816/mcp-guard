# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-05-16

### Added
- `mcp-guard scan` — static scanning of MCP server configs, startup commands,
  tool metadata, JSON schemas, and project directories. Outputs `text`, `json`,
  `sarif`, and `html`.
- `mcp-guard inspect` — minimal stdio MCP client that runs `initialize`,
  `initialized`, and `tools/list` against a server, captures stderr, and
  reports an inventory.
- `mcp-guard fuzz` — schema-driven dynamic fuzzer covering path traversal,
  command injection, SSRF, prompt injection, oversize input, type confusion,
  and secret probing. Safe-mode by default; `--toy-mode` for `examples/` and
  `--allow-unsafe` for advanced users.
- `mcp-guard sandbox` — Docker run command builder with `strict`,
  `filesystem-readonly`, `network-deny`, and `dev` profiles. `--dry-run`
  works without Docker installed.
- `mcp-guard report` — generates standalone offline HTML reports and
  SARIF 2.1.0 for GitHub code scanning.
- `mcp-guard init-example` — copies the bundled example servers into the
  user's working directory.
- Bundled example servers: `safe_server`, `vulnerable_filesystem_server`,
  `vulnerable_shell_server`, `vulnerable_metadata_server`,
  `vulnerable_http_server` (config-only).
- Optional local-LLM semantic judge (`--llm-judge ollama`) targeting Ollama
  or any OpenAI-compatible local endpoint. Disabled by default.
- 35 rules (`MCPG001`–`MCPG035`) covering startup commands, tool poisoning,
  schema risks, dynamic behavior, and sandbox recommendations.
- GitHub Actions CI workflow and reusable `mcp-guard.yml` action snippet.
- Documentation: `threat_model.md`, `rule_catalog.md`, `sandboxing.md`,
  `local_llm.md`, `methodology.md`, `roadmap.md`.

### Known limitations
- Streamable HTTP / SSE transport: detection lives in `config_scan`;
  live HTTP inspection is **experimental** and tracked in
  `docs/roadmap.md`.
- Docker execution on Windows is best-effort; `--dry-run` is the supported
  path on Windows runners.
