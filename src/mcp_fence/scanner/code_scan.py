"""Light source-tree scanner for Python MCP server code.

This is intentionally simple: regex-based, fast, conservative. It is meant
to surface the most common foot-guns when a user points ``mcp-fence scan``
at a project directory. AST-aware analysis is on the roadmap.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Location
from .risk_rules import make_finding
from .secrets import find_secrets, redact

_PY_SHELL_TRUE = re.compile(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", re.DOTALL)
_PY_OS_SYSTEM = re.compile(r"\bos\.system\(")
_PY_OS_POPEN = re.compile(r"\bos\.popen\(")
_PY_EVAL = re.compile(r"\beval\(")
_PY_EXEC = re.compile(r"\bexec\(")
_PY_PICKLE_LOADS = re.compile(r"\bpickle\.loads?\(")
_PY_YAML_LOAD = re.compile(r"\byaml\.load\(\s*[^)]*\)")  # without SafeLoader
_PY_OPEN_PATH = re.compile(r"open\(\s*[^,)]*\)\s*")
_PY_REQUESTS_VERIFY_FALSE = re.compile(r"verify\s*=\s*False")


_SCAN_GLOBS = ("**/*.py",)
_MAX_FILE_SIZE = 256 * 1024  # 256 KB


def scan_directory(root: Path | str) -> list[Finding]:
    root_p = Path(root)
    if not root_p.exists() or not root_p.is_dir():
        return []
    findings: list[Finding] = []
    seen_files = 0
    for pattern in _SCAN_GLOBS:
        for f in root_p.glob(pattern):
            if not f.is_file() or any(
                part in {".venv", "venv", "node_modules", "__pycache__", ".git"}
                for part in f.parts
            ):
                continue
            seen_files += 1
            if seen_files > 500:
                break
            try:
                if f.stat().st_size > _MAX_FILE_SIZE:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(_scan_python_text(text, f))
    return findings


def _line_for(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _add(findings: list[Finding], rule_id: str, *, file: Path, idx: int, text: str, evidence: str, msg: str) -> None:
    findings.append(
        make_finding(
            rule_id,
            description=msg,
            evidence=evidence[:200],
            location=Location(path=str(file), line=_line_for(text, idx)),
            confidence=0.7,
            source="code",
        )
    )


def _scan_python_text(text: str, file: Path) -> list[Finding]:
    findings: list[Finding] = []

    for m in _PY_SHELL_TRUE.finditer(text):
        _add(
            findings,
            "MCPG001",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="subprocess called with shell=True.",
        )
    for m in _PY_OS_SYSTEM.finditer(text):
        _add(
            findings,
            "MCPG001",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="os.system() invokes a shell.",
        )
    for m in _PY_OS_POPEN.finditer(text):
        _add(
            findings,
            "MCPG001",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="os.popen() invokes a shell.",
        )
    for m in _PY_EVAL.finditer(text):
        _add(
            findings,
            "MCPG023",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="Use of `eval()`.",
        )
    for m in _PY_EXEC.finditer(text):
        _add(
            findings,
            "MCPG023",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="Use of `exec()`.",
        )
    for m in _PY_PICKLE_LOADS.finditer(text):
        _add(
            findings,
            "MCPG030",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="`pickle.loads()` deserializes arbitrary objects.",
        )
    for m in _PY_YAML_LOAD.finditer(text):
        if "SafeLoader" not in m.group(0):
            _add(
                findings,
                "MCPG030",
                file=file,
                idx=m.start(),
                text=text,
                evidence=m.group(0),
                msg="`yaml.load()` without SafeLoader executes arbitrary tags.",
            )
    for m in _PY_REQUESTS_VERIFY_FALSE.finditer(text):
        _add(
            findings,
            "MCPG027",
            file=file,
            idx=m.start(),
            text=text,
            evidence=m.group(0),
            msg="TLS verification disabled (`verify=False`).",
        )
    for secret in find_secrets(text):
        findings.append(
            make_finding(
                "MCPG006",
                description=f"Hard-coded secret in source ({secret.name}).",
                evidence=redact(secret.match),
                location=Location(path=str(file), line=_line_for(text, secret.span[0])),
                confidence=0.95,
                source="code",
            )
        )
    return findings
