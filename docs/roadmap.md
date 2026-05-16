# Roadmap

`mcp-fence 0.1.0` is the *vertical slice*: enough to run the full
scan/inspect/fuzz/sandbox/report pipeline against a real stdio MCP
server and ship a usable defensive tool.

## What's in 0.1.0

- Static scan of `mcp.json` configs, single-server JSON, project trees.
- Live `inspect` over stdio: `initialize` → `tools/list`, plus metadata
  + schema rules.
- Schema-driven `fuzz` covering path-traversal, command injection,
  SSRF, prompt injection, oversize, type confusion, missing required,
  extra properties, env probes.
- Safe-by-default fuzz gating; `--toy-mode` for bundled examples;
  `--allow-unsafe` for use inside the sandbox.
- Docker `sandbox` builder with `strict`, `filesystem-readonly`,
  `network-deny`, `dev` profiles. `--dry-run` works without Docker.
- Reports: `text`, `json`, `sarif` 2.1.0, offline `html`.
- Optional local LLM judge (Ollama or OpenAI-compatible).
- GitHub Actions CI workflow and reusable `mcp-fence.yml` snippet.

## Known gaps in 0.1.0

These are tracked here and *do not* block the v0.1 acceptance.

### Transport

- **Streamable HTTP / SSE live inspection** — currently the config
  scanner catches risky HTTP transports (`MCPG007`, `MCPG008`) but the
  inspector does not talk to a running HTTP server. The protocol layer
  is structured so adding an HTTP transport is a single file.
- **WebSocket transport** — same shape, lower priority.

### Source-tree scanning

- The Python `code_scan` is regex-based. An AST walk is on deck for
  v0.2 so we can detect indirect `subprocess` calls and dataflow into
  high-risk sinks.
- TypeScript / Node ecosystem support — v0.3.

### Dynamic fuzzing

- The SSRF detector currently checks whether the tool *rejects* the
  URL; it does not stand up a local capture server. v0.2 will add an
  optional local trap server so we can prove the tool actually fetched
  the URL.
- Stateful fuzzing (chained tool calls, session-aware servers) — v0.3.

### Sandbox

- Windows-native sandboxing (e.g. Job Objects, App Containers) is on
  the roadmap. Today Windows users get `--dry-run` and are encouraged
  to run mcp-fence inside WSL2 / Docker for the `--execute` path.
- Rootless `podman` parity — should just work; need to test the
  command builder.

### LLM judge

- Multi-tool batch judgements (currently one call per tool).
- A pre-fetched local "tool poisoning classifier" so users can run
  without any LLM endpoint at all (v0.3).

## v0.2 candidates

- AST-based Python scanner.
- HTTP/SSE live inspector.
- Local SSRF capture server.
- Pre-trained tool-poisoning classifier.
- More language ecosystems (Node / Go).
- `mcp-fence diff` for comparing inventories between versions
  (rug-pull detection).

## v0.3+

- Continuous monitoring mode: watch a directory, re-run the scan on
  every change.
- Pre-commit hook bundle.
- Integrations with security scanners that already understand SARIF
  (Github code scanning, GitLab, Sonar).
