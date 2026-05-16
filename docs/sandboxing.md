# Sandboxing

`mcp-fence sandbox` generates a `docker run` command that wraps any
stdio MCP server with conservative defaults. The four built-in
profiles trade off isolation against developer ergonomics.

## Profiles

| Profile                | Network   | Rootfs     | Caps drop | no-new-privs | Use when                                 |
| ---------------------- | --------- | ---------- | --------- | ------------ | ---------------------------------------- |
| `strict`               | `none`    | read-only  | yes       | yes          | Production / untrusted server / CI       |
| `filesystem-readonly`  | `bridge`  | read-only  | yes       | yes          | Tool needs outbound HTTP but no writes   |
| `network-deny`         | `none`    | writable   | yes       | yes          | Tool needs temp files but no network     |
| `dev`                  | `bridge`  | writable   | no        | yes          | Your own server during development       |

All profiles set:

- `--rm -i` so the container goes away when the session ends.
- Memory cap (512 MB), CPU cap (1.0 vCPU), pids cap (256).
- `--tmpfs /tmp` and `--tmpfs /run` so `mktemp` still works inside a
  read-only rootfs.
- `PYTHONUNBUFFERED=1` and `PYTHONIOENCODING=utf-8` so newline-delimited
  JSON-RPC works on Linux containers.

## Why these flags

- **`--network none` (strict, network-deny):** removes the SSRF and
  data-exfiltration surface entirely. If the tool still functions you've
  confirmed it doesn't need the network.
- **`--read-only`:** the server cannot rewrite its own code, drop a
  systemd unit, or leave persistent artefacts. Anything it genuinely
  needs to write goes via the tmpfs mounts.
- **`--cap-drop ALL`:** drops Linux capabilities like
  `CAP_NET_BIND_SERVICE` and `CAP_DAC_OVERRIDE`. Most MCP servers do
  not need any of these.
- **`--security-opt no-new-privileges`:** even if the server somehow
  invokes a setuid binary, it cannot escalate.
- **`--pids-limit`, `--memory`, `--cpus`:** prevent a misbehaving or
  malicious server from making the host unusable.
- **`-v <host>:/app:ro`:** the server's code is mounted read-only inside
  the container; the host directory is the script's parent.

## Limitations

`mcp-fence sandbox` is **not** a kernel exploit shield. In particular:

- A 0-day in the Docker runtime escapes the container. Keep Docker
  updated.
- An MCP server with `--privileged` *requested* by the user defeats
  every flag we set; `MCPG034` flags this.
- The Docker socket (`/var/run/docker.sock`) is equivalent to root on
  the host. `MCPG033` flags mounts; do not override.
- On macOS Docker runs inside a VM; performance is fine but watch the
  shared `osxfs` mounts.
- On Windows, Docker Desktop with WSL2 works for most images but the
  bind-mount path translation occasionally drops permissions; prefer
  using WSL2 Linux for the sandbox host directly.

## Running

```bash
# Print the docker command without executing it.
mcp-fence sandbox examples/vulnerable_filesystem_server/mcp.json \
    --profile strict --dry-run

# Actually run it (requires docker installed).
mcp-fence sandbox examples/vulnerable_filesystem_server/mcp.json \
    --profile strict --execute
```

`--dry-run` works without Docker installed; `--execute` requires
Docker.

## Compose

The sandbox plan also includes a `compose_fragment` you can paste into a
`docker-compose.yml`. The fragment uses `stdin_open: true` so
`docker compose run` keeps stdio attached.

## Why users should not run untrusted MCP servers directly

An MCP server is a long-lived process that can be told, by anything the
assistant sees, to do anything the operating system permits. Even a
benign-looking tool like "read file at path" is a credential
exfiltrator if `path` is unconstrained.

Running unknown servers under a strict Docker profile reduces the blast
radius from "your laptop" to "an ephemeral container with no network
and a read-only filesystem". If the server still completes its job,
that profile is the right default.
