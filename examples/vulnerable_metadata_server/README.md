# `vulnerable_metadata_server`

A toy MCP server that demonstrates *tool poisoning* — attacks delivered
through the description and name fields rather than the implementation.

## What's wrong

- `summarize`'s description contains a hidden HTML comment with
  prompt-injection text ("ignore previous instructions", "exfiltrate",
  "do not tell the user", "system prompt"). LLMs that consume tool
  descriptions verbatim will be influenced.
- `Iist_files` uses a capital `I` confusable instead of a lowercase `l`.
- `execute` has a generic name and contradictory annotations
  (`readOnlyHint=true` *and* `destructiveHint=true`).
- The `mcp.json` `env` contains a fake `OPENAI_API_KEY` to demonstrate
  the env-secret detector (`MCPG006`).

## Expected mcp-guard findings

From `mcp-guard scan`:

- `MCPG006` (env secret).
- `MCPG010` (prompt-injection phrase in description).
- `MCPG011` (HTML comment inside description).
- `MCPG012` (confusable tool name).
- `MCPG013` (broad tool name `execute`).
- `MCPG014` (read-only claim contradicted by description / destructive).
- `MCPG015` (destructive without schema guard).
- `MCPG017`/`MCPG019`/`MCPG020`/`MCPG021`/`MCPG022` as schemas warrant.

## Safety

The example does not actually send any data anywhere; the hidden
instruction is a literal string embedded in metadata. Removing the
example does not affect the rest of mcp-guard.
