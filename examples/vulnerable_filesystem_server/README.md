# `vulnerable_filesystem_server`

A toy MCP server with an arbitrary-file-read sink. Used to demonstrate
that `mcp-fence fuzz` actually detects path-traversal.

## What's wrong

- `read_file(path)` opens any path the caller provides.
- The schema's `path` parameter has no `pattern`, `enum`, or
  `maxLength`.
- `allowedDirectories` in `mcp.json` is set to `/` to flag MCPG009.

## Expected mcp-fence findings

- `MCPG009` (broad allowlist) — from `mcp.json`.
- `MCPG021` (high-risk parameter without pattern/enum) — from the schema.
- `MCPG022` (high-risk parameter name `path`) — from the schema.
- `MCPG020` (string with no `maxLength`) — from the schema.
- `MCPG025` (path traversal succeeded) — from `mcp-fence fuzz`.
- `MCPG031` (secret-shaped content in tool output) — from `mcp-fence fuzz`
  when the fuzzer reads `fake_secret.txt`.

## Safety

The "secret" file is fake and self-contained. The fuzzer aims at this
file rather than real OS credentials.
