# `vulnerable_shell_server`

A toy MCP server that proxies its argument directly into a shell. Used to
demonstrate command-injection detection.

## What's wrong

- `run_command(command)` invokes `subprocess.run(command, shell=True)`
  with attacker-controlled input.
- `echo_args(text)` similarly uses `shell=True`.
- The tool name `run_command` matches `MCPG023`.
- The argument name `command` lacks a `pattern`/`enum` (`MCPG021`,
  `MCPG022`).
- The `mcp.json` start command is `bash -c …`, which fires `MCPG001`.

## Expected mcp-guard findings

- `MCPG001` (shell-style start command).
- `MCPG023` (RCE-implying tool name).
- `MCPG021`, `MCPG022`, `MCPG020` on the `command` parameter.
- `MCPG026` (command injection marker observed) — under `--toy-mode` or
  `--allow-unsafe`.

## Safety

The marker payload is `echo MCPG_FUZZ_MARKER_8f2a`. mcp-guard never sends
`rm`, `mv`, or other destructive payloads. Even so, only run this server
inside the bundled Docker sandbox or via `mcp-guard fuzz --toy-mode`.
