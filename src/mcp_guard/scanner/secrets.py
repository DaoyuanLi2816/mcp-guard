"""Pattern-based secret detection used by both config and dynamic scanners."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..constants import SECRET_PATTERNS


@dataclass(frozen=True)
class SecretMatch:
    name: str
    match: str
    span: tuple[int, int]


_COMPILED = [(name, re.compile(pat)) for name, pat in SECRET_PATTERNS]


def find_secrets(text: str) -> list[SecretMatch]:
    """Scan *text* for known secret patterns.

    Returns the matched substring; callers are expected to redact it before
    putting it into a finding.
    """
    if not text:
        return []
    out: list[SecretMatch] = []
    for name, pat in _COMPILED:
        for m in pat.finditer(text):
            out.append(SecretMatch(name=name, match=m.group(0), span=(m.start(), m.end())))
    return out


_SECRET_LIKE_KEY = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|access[_-]?key|client[_-]?secret)$"
)
_ENV_PLACEHOLDER = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Z_]+|<[^>]+>)\s*$")


def env_value_looks_secret(key: str, value: object) -> bool:
    """Return True if *value* under env-key *key* looks like a plaintext secret.

    Placeholders like ``${OPENAI_API_KEY}`` or ``<your-token>`` are ignored
    so reasonable templates don't trigger.
    """
    if not isinstance(value, str) or not value:
        return False
    if _ENV_PLACEHOLDER.match(value):
        return False
    if find_secrets(value):
        return True
    if _SECRET_LIKE_KEY.search(key):
        stripped = value.strip()
        if len(stripped) >= 16 and re.search(r"[A-Za-z]", stripped) and re.search(r"[0-9]", stripped):
            return True
    return False


def redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2 + 3:
        return "***"
    return f"{s[:keep]}***{s[-keep:]}"
