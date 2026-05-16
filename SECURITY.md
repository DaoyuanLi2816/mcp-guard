# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you find a security issue in `mcp-guard` itself (the scanner, fuzzer,
sandbox runner, or report generator):

1. **Do not** open a public GitHub issue.
2. Email the maintainers, or open a GitHub *security advisory* via the
   "Security" tab on the project repository.
3. Include reproduction steps, affected version, and impact assessment.

We aim to acknowledge reports within 5 business days.

## Scope: what `mcp-guard` is and is not

`mcp-guard` is a **defensive** local tool used by MCP server authors and
operators to audit their own servers. It is **not** an offensive tool and
is not intended for unauthorized testing of third-party services.

### Safety guarantees

- **Non-destructive.** Fuzzing payloads are harmless; the marker payload
  used to detect command injection is `echo MCP_GUARD_MARKER` (or an
  equivalent that creates/reads a clearly-named file under the OS temp
  directory). No `rm`, `mv`, `chmod`, or destructive system calls are
  ever emitted.
- **Local-first.** No code, configuration, or scan result is ever uploaded.
  The optional LLM judge talks to a *local* endpoint only (Ollama,
  vLLM, or any OpenAI-compatible local server).
- **No public-network scanning.** SSRF payloads test the *URL validation
  behaviour* of the target tool. The default fuzz runner does not initiate
  outbound HTTP requests itself.
- **Safe path probing.** Path-traversal fuzzing aims at fake secret files
  inside the scanned project. It never targets `/etc/shadow`,
  `~/.ssh/id_*`, or other real sensitive paths.

### What you opt into with `--allow-unsafe`

`--allow-unsafe` lets the fuzzer pass through the unsafe-tool gate so it
can call tools whose name or argument schema looks shell-like (`command`,
`shell`, `exec`, `code`, `script`, ...). This is appropriate inside the
provided Docker sandbox or against your own toy servers; it should **not**
be used against unfamiliar third-party MCP servers running on your
machine.

### Use of examples

The `examples/vulnerable_*` servers in this repository contain
intentionally insecure code for testing. Do **not** run them outside the
sandbox or expose them on a network interface.
