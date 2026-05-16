"""Shared pytest fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = PROJECT_ROOT / "examples"


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def examples_dir() -> Path:
    return EXAMPLES_DIR


@pytest.fixture
def python_exe() -> str:
    return sys.executable


@pytest.fixture
def write_mcp_config(tmp_path: Path, python_exe: str):
    """Materialise an mcp.json that points at *server_path* via `sys.executable`.

    This avoids the "python" shim issue on Windows where PATH points at the
    Microsoft Store stub.
    """

    def _make(server_path: Path, *, name: str = "test-server", extra_env: dict | None = None) -> Path:
        config = {
            "mcpServers": {
                name: {
                    "command": python_exe,
                    "args": [str(server_path)],
                    "transport": "stdio",
                    "env": extra_env or {},
                }
            }
        }
        out = tmp_path / "mcp.json"
        out.write_text(json.dumps(config), encoding="utf-8")
        return out

    return _make


@pytest.fixture
def env_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")
    yield


def _docker_available() -> bool:
    import shutil

    return shutil.which("docker") is not None


@pytest.fixture(scope="session")
def docker_available() -> bool:
    return _docker_available()


@pytest.fixture(autouse=True)
def _unbuffered_stdio(monkeypatch):
    monkeypatch.setenv("PYTHONUNBUFFERED", "1")
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    yield
