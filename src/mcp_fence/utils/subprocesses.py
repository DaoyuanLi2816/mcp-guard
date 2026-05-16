"""Subprocess helpers tuned for stdio MCP clients on Windows/macOS/Linux."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from .logging import get_logger

log = get_logger()


def resolve_executable(cmd: str, cwd: Path | None = None) -> str:
    """Resolve ``cmd`` to an absolute path if possible.

    Falls back to the original string so subprocess can still raise the
    canonical ``FileNotFoundError`` if needed.
    """
    if not cmd:
        return cmd
    if os.path.isabs(cmd) and os.path.exists(cmd):
        return cmd
    found = shutil.which(cmd)
    if found:
        return found
    if cwd is not None:
        candidate = (cwd / cmd).resolve()
        if candidate.exists():
            return str(candidate)
    return cmd


def kill_tree(proc: subprocess.Popen) -> None:
    """Terminate a process and try to take its children with it."""
    if proc.poll() is not None:
        return
    if sys.platform.startswith("win"):
        with suppress(Exception):
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        with suppress(Exception):
            proc.kill()
    else:
        with suppress(ProcessLookupError, OSError):
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, 15)
            except (AttributeError, OSError):
                proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError, OSError):
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, 9)
                except (AttributeError, OSError):
                    proc.kill()


def spawn_stdio(
    argv: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Spawn a child suitable for line-delimited JSON-RPC over stdio.

    ``argv[0]`` is resolved before launch so a missing interpreter raises a
    clean ``FileNotFoundError`` instead of a Windows-specific OSError.
    """
    if not argv:
        raise ValueError("argv must be non-empty")
    resolved = list(argv)
    resolved[0] = resolve_executable(resolved[0], cwd)

    popen_kwargs: dict[str, object] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "bufsize": 0,
        "cwd": str(cwd) if cwd else None,
    }
    full_env = os.environ.copy()
    if env:
        full_env.update({k: str(v) for k, v in env.items()})
    # MCP servers expect to talk JSON-RPC, not be a chat window. Make sure
    # any Python child flushes stdout line by line.
    full_env.setdefault("PYTHONUNBUFFERED", "1")
    full_env.setdefault("PYTHONIOENCODING", "utf-8")
    popen_kwargs["env"] = full_env

    if not sys.platform.startswith("win"):
        popen_kwargs["start_new_session"] = True
    else:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    log.debug("spawn_stdio argv=%s cwd=%s", resolved, cwd)
    return subprocess.Popen(resolved, **popen_kwargs)  # type: ignore[arg-type]
