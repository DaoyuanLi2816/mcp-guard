"""mcp-guard: local-first security scanner, inspector, fuzzer, sandbox, and report
generator for Model Context Protocol servers."""

from .models import (
    Finding,
    FuzzCase,
    FuzzResult,
    Inventory,
    ScanResult,
    Severity,
    ToolSpec,
)

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "FuzzCase",
    "FuzzResult",
    "Inventory",
    "ScanResult",
    "Severity",
    "ToolSpec",
    "__version__",
]
