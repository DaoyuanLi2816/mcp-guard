# `vulnerable_http_server`

A toy *configuration* that demonstrates the HTTP/SSE transport risks.
mcp-guard's live HTTP transport is on the roadmap; for v0.1 this example
is detected purely via `mcp.json` scanning.

## What's wrong

- `transport: streamable-http`.
- `url: http://0.0.0.0:8765/mcp` — binds to all interfaces (`MCPG007`).
- No `Authorization` header / token (`MCPG008`).
- `allowedDirectories: ["/"]` (`MCPG009`).
- `env.API_TOKEN` is a plaintext fake secret (`MCPG006`).

## Expected mcp-guard findings

- `MCPG006`, `MCPG007`, `MCPG008`, `MCPG009`.

## Safety

The stub HTTP server only echoes the request body and does no privileged
work. Even so, only run it on an isolated host.
