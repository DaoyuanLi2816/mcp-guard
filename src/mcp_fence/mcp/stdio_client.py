"""Self-contained newline-delimited JSON-RPC client.

This is the canonical transport that v0.1 supports. It is written to be
robust against:

- non-JSON output on stdout (treated as protocol warnings, not crashes)
- the server dying mid-call
- the server hanging (timeout via the queue's ``get(timeout=…)``)
- partial lines (the read thread accumulates until newline)
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from ..utils.logging import get_logger
from ..utils.subprocesses import kill_tree, spawn_stdio
from .protocol import (
    build_notification,
    build_request,
    initialize_params,
    initialized_notification,
    is_response_for,
    parse_error,
)

log = get_logger()


class MCPClientError(RuntimeError):
    pass


class StdioTransportError(MCPClientError):
    pass


class StdioTimeout(MCPClientError):
    pass


class McpStdioClient:
    """Newline-delimited JSON-RPC client for a child MCP server."""

    def __init__(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        default_timeout: float = 10.0,
    ):
        self.argv = list(argv)
        self.cwd = cwd
        self.env = env
        self.default_timeout = default_timeout

        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_q: queue.Queue[bytes | None] = queue.Queue()
        self._stderr_lines: list[str] = []
        self._stderr_lock = threading.Lock()
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._protocol_warnings: list[str] = []
        self._closed = False
        self._server_info: dict[str, Any] = {}
        self._capabilities: dict[str, Any] = {}
        self._protocol_version: str | None = None

    # ---- lifecycle ----

    @property
    def proc(self) -> subprocess.Popen[bytes]:
        if not self._proc:
            raise MCPClientError("Client not started")
        return self._proc

    @property
    def server_info(self) -> dict[str, Any]:
        return self._server_info

    @property
    def capabilities(self) -> dict[str, Any]:
        return self._capabilities

    @property
    def protocol_version(self) -> str | None:
        return self._protocol_version

    @property
    def protocol_warnings(self) -> list[str]:
        return list(self._protocol_warnings)

    def start(self) -> None:
        if self._proc:
            return
        try:
            self._proc = spawn_stdio(self.argv, cwd=self.cwd, env=self.env)
        except FileNotFoundError as e:
            raise StdioTransportError(
                f"Could not launch MCP server `{' '.join(self.argv)}`: {e}"
            ) from e
        except OSError as e:
            raise StdioTransportError(f"Failed to spawn MCP server: {e}") from e

        self._stdout_thread = threading.Thread(
            target=self._read_stdout, name="mcp-fence-stdout", daemon=True
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr, name="mcp-fence-stderr", daemon=True
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._proc is None:
            return
        with self._suppress():
            if self._proc.stdin and not self._proc.stdin.closed:
                self._proc.stdin.close()
        kill_tree(self._proc)
        with self._suppress():
            if self._proc.stdout:
                self._proc.stdout.close()
        with self._suppress():
            if self._proc.stderr:
                self._proc.stderr.close()

    def __enter__(self) -> McpStdioClient:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # ---- I/O ----

    def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            for raw in iter(self._proc.stdout.readline, b""):
                if not raw:
                    break
                self._stdout_q.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            self._stdout_q.put(None)

    def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        try:
            for raw in iter(self._proc.stderr.readline, b""):
                if not raw:
                    break
                try:
                    s = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    continue
                with self._stderr_lock:
                    self._stderr_lines.append(s)
                    if len(self._stderr_lines) > 1000:
                        self._stderr_lines.pop(0)
        except (OSError, ValueError):
            pass

    def stderr_text(self) -> str:
        with self._stderr_lock:
            return "\n".join(self._stderr_lines)

    def _send(self, payload: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise StdioTransportError("Server stdin not available")
        if self._proc.poll() is not None:
            raise StdioTransportError(
                f"MCP server exited (code={self._proc.returncode}) before message could be sent. "
                f"stderr: {self.stderr_text()[:500]}"
            )
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"
        try:
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise StdioTransportError(f"Failed to write to MCP server stdin: {e}") from e

    def _recv_response_for(self, request_id: int, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StdioTimeout(
                    f"Timed out after {timeout:.2f}s waiting for response id={request_id}"
                )
            try:
                raw = self._stdout_q.get(timeout=remaining)
            except queue.Empty as e:
                raise StdioTimeout(
                    f"Timed out after {timeout:.2f}s waiting for response id={request_id}"
                ) from e
            if raw is None:
                code = self._proc.returncode if self._proc else None
                raise StdioTransportError(
                    f"MCP server stdout closed (exit code={code}). stderr: "
                    f"{self.stderr_text()[:500]}"
                )
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except json.JSONDecodeError:
                # Non-JSON line on stdout — record as warning, skip.
                self._protocol_warnings.append(text[:300])
                continue
            if isinstance(msg, dict) and is_response_for(msg, request_id):
                return msg
            # Notifications / unrelated responses — ignore but note.
            if isinstance(msg, dict) and msg.get("method"):
                continue
            self._protocol_warnings.append(f"unexpected message: {text[:200]}")

    # ---- public protocol ----

    def initialize(self, timeout: float | None = None) -> dict[str, Any]:
        req = build_request("initialize", initialize_params())
        self._send(req)
        resp = self._recv_response_for(req["id"], timeout or self.default_timeout)
        err = parse_error(resp)
        if err:
            raise MCPClientError(f"initialize failed: {err}")
        result = resp.get("result") or {}
        self._server_info = result.get("serverInfo") or {}
        self._capabilities = result.get("capabilities") or {}
        self._protocol_version = result.get("protocolVersion")
        # Per spec: send initialized notification after a successful initialize.
        self._send(initialized_notification())
        return result

    def tools_list(self, timeout: float | None = None) -> list[dict[str, Any]]:
        req = build_request("tools/list", {})
        self._send(req)
        resp = self._recv_response_for(req["id"], timeout or self.default_timeout)
        err = parse_error(resp)
        if err:
            raise MCPClientError(f"tools/list failed: {err}")
        result = resp.get("result") or {}
        tools = result.get("tools") or []
        if not isinstance(tools, list):
            return []
        return tools

    def tools_call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        req = build_request("tools/call", {"name": name, "arguments": arguments})
        self._send(req)
        resp = self._recv_response_for(req["id"], timeout or self.default_timeout)
        return resp

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send(build_notification(method, params))

    @staticmethod
    def _suppress():  # context manager that swallows everything
        class _S:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return True

        return _S()


def connect_stdio(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    default_timeout: float = 10.0,
) -> McpStdioClient:
    client = McpStdioClient(argv, cwd=cwd, env=env, default_timeout=default_timeout)
    client.start()
    return client
