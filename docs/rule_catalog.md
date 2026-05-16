# Rule catalog

Every rule has a stable identifier (`MCPGNNN`) so reports stay diff-able
across versions. The canonical source is
[`src/mcp_fence/constants.py`](../src/mcp_fence/constants.py); this
document mirrors it with extra detail.

Legend: **C** = critical, **H** = high, **M** = medium, **L** = low,
**I** = info.

## A. Startup-command / config (`startup-command`, `transport-binding`, `secrets`)

### `MCPG001` — Server start command uses a shell  (M)
- **Detect:** `command` is `sh`/`bash`/`zsh`/`pwsh`/`cmd` with `-c`/`/c`,
  or `subprocess(..., shell=True)` in source.
- **Why it matters:** Shell interpretation of arguments turns crafted
  config values into arbitrary commands.
- **False positives:** Some tools genuinely need a shell wrapper for
  environment setup. Move that into a vetted launcher script and call
  the launcher directly.
- **Fix:** Invoke the interpreter with an argv list.

### `MCPG002` — Start command downloads and executes code  (C)
- **Detect:** Regex match for `curl | sh`, `wget | sh`,
  `base64 -d | sh`, etc.
- **Why:** Supply-chain compromise.
- **Fix:** Vendor and review the script; call it from a local path.

### `MCPG003` — `sudo` in start command  (H)
- **Detect:** Token `sudo` anywhere in the command line.
- **Fix:** Run as an unprivileged user; use Docker for isolation.

### `MCPG004` — Destructive operation in start command  (H)
- **Detect:** `rm -rf`, `mkfs`, `chmod 777`.
- **Fix:** Move setup steps out of the start command.

### `MCPG005` — Sensitive host path in start command  (H)
- **Detect:** References to `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/`,
  `/var/run/docker.sock`.
- **Fix:** Don't touch credential directories from start commands.

### `MCPG006` — Plaintext secret in `env`  (H)
- **Detect:** Value matches a known secret pattern (AWS key, GitHub
  token, OpenAI key, Slack token, private-key header), OR an env key
  like `*_KEY`/`*_TOKEN`/`*_SECRET` with a 16+ char value mixing
  letters/digits. Placeholders like `${VAR}` are ignored.
- **Fix:** Read secrets from a vault or at runtime.

### `MCPG007` — HTTP transport bound to `0.0.0.0`  (H)
- **Detect:** URL host or `host` field is `0.0.0.0` or `[::]`.
- **Fix:** Bind to `127.0.0.1` or a Unix socket.

### `MCPG008` — HTTP/SSE transport without authentication  (H)
- **Detect:** HTTP-family transport with no Authorization-shaped header
  / token / OAuth config.
- **Fix:** Require a bearer token or OAuth; bind locally.

### `MCPG009` — Broad filesystem allowlist  (M)
- **Detect:** `allowedDirectories` / `roots` includes `/`, `~`,
  `$HOME`, or `**`.
- **Fix:** List specific subdirectories.

## B. Tool metadata (`tool-metadata`)

### `MCPG010` — Prompt-injection phrase in description  (H)
- **Detect:** Substring match against a phrase list
  (`ignore previous instructions`, `do not tell the user`, `exfiltrate`,
  `system prompt`, …). Optionally augmented by the local LLM judge.
- **False positives:** Documentation that quotes attack phrasing should
  fence the text out, e.g. with `<example>` tags. Re-word to avoid the
  exact phrases.
- **Fix:** Remove the phrase; rewrite the description as plain prose.

### `MCPG011` — Hidden instructions in description  (H)
- **Detect:** HTML comments `<!-- … -->`, zero-width characters,
  hidden-markdown references (`[//]: # (…)`).
- **Fix:** Strip the hidden content; render descriptions as plain text.

### `MCPG012` — Confusable tool name  (M)
- **Detect:** Unicode confusables (Cyrillic letters in Latin words) and
  ASCII visual confusables (`Iist_files` vs `list_files`).
- **Fix:** Use ASCII names that do not collide with well-known tools.

### `MCPG013` — Overly broad tool name  (L)
- **Detect:** Name in the set `{execute, run, admin, shell, eval, do,
  go, exec, command}`.
- **Fix:** Use an action-scoped name.

### `MCPG014` — Read-only claim contradicted by description  (M)
- **Detect:** `readOnlyHint: true` annotation with description text that
  mentions `write`/`delete`/`execute`/`modify`/`run command`.
- **Fix:** Reconcile the description, schema, and annotation.

### `MCPG015` — Destructive annotation without schema guard  (M)
- **Detect:** `destructiveHint: true` but `additionalProperties` is
  unrestricted, or there are no `required` parameters.
- **Fix:** Lock down the schema and require explicit confirmation.

### `MCPG016` — Read-only contradicted by parameters  (M)
- **Detect:** `readOnlyHint: true` but parameters include
  `command`/`shell`/`exec`/`code`/`eval`/`script`/`webhook`/`callback`.
- **Fix:** Set `readOnlyHint: false` or remove the parameter.

### `MCPG023` — Name implies arbitrary execution  (H)
- **Detect:** Tool name contains tokens like `shell`, `exec`, `eval`,
  `run_command`, `subprocess`, `system_call`, `bash`.
- **Fix:** Replace with a narrowly scoped tool; require sandbox + per-
  call confirmation if RCE is unavoidable.

### `MCPG024` — Long or HTML-formatted description  (L)
- **Detect:** Description > 1500 chars or contains many newlines.
- **False positives:** Genuinely long documentation. Move the long
  prose to README and keep the tool description short.

## C. Schemas (`schema`)

### `MCPG017` — Missing `type: object`  (L)
- **Fix:** Set `type: object`.

### `MCPG018` — Dangerous tool has no `required`  (L)
- **Fix:** Mark the operational parameter as required.

### `MCPG019` — `additionalProperties` not restricted  (L)
- **Fix:** Set `additionalProperties: false`.

### `MCPG020` — Unbounded string parameter  (L)
- **Fix:** Add a reasonable `maxLength`.

### `MCPG021` — High-risk parameter lacks pattern/enum  (M)
- **Fix:** Add a `pattern` or `enum` reflecting the allowed surface.

### `MCPG022` — High-risk parameter name without constraint  (M)
- **Detect:** Parameter name in the high-risk set (`command`, `cmd`,
  `path`, `url`, `webhook`, `token`, …) **and** the schema has no
  `pattern`/`enum`/`maxLength`.
- **Fix:** Constrain the parameter, or rename to something narrower.

## D. Dynamic behaviour (`dynamic-behavior`, `protocol`)

### `MCPG025` — Path traversal succeeded  (C)
- **Detect:** Tool response includes the contents of a planted fake
  secret file (`FAKE_SECRET=…`, `AKIAFAKE…`, …).
- **Fix:** Canonicalise paths; enforce an allowlist.

### `MCPG026` — Command injection marker observed  (C)
- **Detect:** Tool response contains the safe injection marker
  (`MCPG_FUZZ_MARKER_8f2a`).
- **Fix:** Use argv-form subprocess; never `shell=True` with
  concatenated input.

### `MCPG027` — SSRF payload accepted  (H)
- **Detect:** Tool accepts URLs targeting loopback / link-local /
  metadata IPs without rejecting them.
- **Fix:** Validate URLs against an allowlist; deny RFC1918 and
  link-local.

### `MCPG028` — Prompt injection reflected  (M)
- **Detect:** Tool returns the attacker prompt verbatim without
  envelope marking.
- **Fix:** Wrap tool output in an envelope and treat it as untrusted.

### `MCPG029` — Oversize-input hang  (M)
- **Detect:** Server times out on a large input.
- **Fix:** Add request-size caps.

### `MCPG030` — Malformed input accepted  (M)
- **Detect:** Server returns a non-error response for input violating
  the declared schema (type confusion, extra properties, missing
  required).
- **Fix:** Validate against JSON schema before dispatch.

### `MCPG031` — Sensitive value in tool output  (H)
- **Detect:** Tool output matches a secret pattern.
- **Fix:** Filter or redact before returning.

### `MCPG032` — Stack trace / absolute path leak  (L)
- **Detect:** Response contains `Traceback (...)` or absolute paths
  (`/home/…`, `C:\…`).
- **Fix:** Return safe error messages; log details server-side.

### `MCPG035` — Server failed to respond within timeout  (L)
- **Detect:** Initialize / tools/list / tools/call exceeded the
  configured timeout.
- **Fix:** Tune the timeout; investigate the hang.

## E. Sandbox (`sandbox`)

### `MCPG033` — Docker socket exposed to server  (C)
- **Detect:** Config or start command references
  `/var/run/docker.sock`.
- **Fix:** Never mount the Docker socket into an MCP container.

### `MCPG034` — Privileged or no-new-privileges off  (H)
- **Detect:** `--privileged` flag in start command or config.
- **Fix:** Drop all capabilities by default and set
  `no-new-privileges`.
