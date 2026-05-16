# `safe_server`

A minimal, well-behaved MCP server used as a positive baseline by
mcp-guard's tests and tutorials.

## Tools

- `read_allowed_file(filename)` — reads a single file from `data/`. The
  schema constrains `filename` to a basename matching
  `^[A-Za-z0-9_.-]+$` with `maxLength: 64`. The implementation
  canonicalises paths and rejects anything outside `data/`.
- `list_allowed_files()` — lists files inside `data/`.

## Run

```bash
python examples/safe_server/server.py
```

The server speaks newline-delimited JSON-RPC on stdio. `mcp-guard inspect
examples/safe_server/mcp.json` should report two tools and zero findings.

## Why is it safe?

- Path is restricted to the allowlist directory.
- Schema is constrained (`pattern`, `maxLength`, `additionalProperties:
  false`).
- The implementation does not call a shell.
- The `readOnlyHint` annotation matches behaviour.
