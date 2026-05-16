"""Inspect a :class:`FuzzResult` and attach :class:`Finding` objects."""

from __future__ import annotations

import re

from ..constants import FUZZ_MARKER
from ..models import Finding, FuzzCase, FuzzResult, Location
from ..scanner.risk_rules import make_finding
from ..scanner.secrets import find_secrets, redact

_FAKE_SECRET_MARKERS = [
    "FAKE_SECRET",
    "AKIAFAKE0000FAKEKEY0",
    "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234",
]
_STACK_TRACE_RE = re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+|at [A-Za-z0-9_.]+\(.+:\d+\)")
_ABS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/(?:home|Users|root|etc|var|tmp))\S+", re.MULTILINE)
_TIMEOUT_MARKER = "MCP_GUARD_TIMEOUT"


def _location_for(case: FuzzCase) -> Location:
    return Location(tool=case.tool_name, parameter=case.payload_category)


def _detect_marker(text: str) -> bool:
    return FUZZ_MARKER in text


def _detect_fake_secret(text: str) -> bool:
    return any(marker in text for marker in _FAKE_SECRET_MARKERS)


def _detect_real_secret(text: str) -> list[str]:
    return [redact(m.match) + f" ({m.name})" for m in find_secrets(text)]


def _detect_prompt_reflection(text: str, payload: str) -> bool:
    if not payload:
        return False
    # If a substantial chunk of the payload is reflected verbatim and the
    # tool didn't wrap it in any envelope, treat as reflection.
    if len(payload) < 24:
        return False
    return payload[:48] in text


def _detect_stack_trace(text: str) -> str | None:
    m = _STACK_TRACE_RE.search(text)
    return m.group(0)[:200] if m else None


def _detect_abs_path(text: str) -> str | None:
    m = _ABS_PATH_RE.search(text)
    return m.group(0)[:200] if m else None


def inspect_fuzz_result(result: FuzzResult) -> None:
    """Mutates *result*: populates ``detected_signals`` and ``findings``."""
    if result.skipped:
        return
    case = result.case
    text = result.response_text or ""

    payload_value = ""
    for v in case.arguments.values():
        if isinstance(v, str) and len(v) > len(payload_value):
            payload_value = v

    location = _location_for(case)
    is_error = result.response_ok is False or "isError" in text.lower()[:20]

    if case.payload_category == "command-injection":
        if _detect_marker(text):
            result.detected_signals.append("command-injection-marker")
            result.boundary_violation = True
            result.findings.append(
                make_finding(
                    "MCPG026",
                    description=(
                        f"Tool `{case.tool_name}` executed an injected marker "
                        "command and returned its output."
                    ),
                    evidence=text[:200],
                    location=location,
                    source="dynamic",
                    confidence=0.95,
                )
            )

    if case.payload_category == "path-traversal":
        if _detect_fake_secret(text):
            result.detected_signals.append("path-traversal-success")
            result.boundary_violation = True
            result.findings.append(
                make_finding(
                    "MCPG025",
                    description=(
                        f"Tool `{case.tool_name}` returned the contents of the "
                        "planted fake-secret file via a traversal payload."
                    ),
                    evidence=text[:200],
                    location=location,
                    source="dynamic",
                    confidence=0.95,
                )
            )

    if case.payload_category == "ssrf":
        # We don't actually make outbound requests; we observe whether the
        # tool validated the URL up-front or treated it like a real input.
        ssrf_url = ""
        for v in case.arguments.values():
            if isinstance(v, str) and (
                v.startswith("http") or v.startswith("file://") or v.startswith("gopher://")
            ):
                ssrf_url = v
                break
        if ssrf_url and not is_error:
            if ssrf_url in text or text == "" or text.lower()[:8].startswith(("ok", "fetched", "echo")):
                result.detected_signals.append("ssrf-not-validated")
                result.findings.append(
                    make_finding(
                        "MCPG027",
                        description=(
                            f"Tool `{case.tool_name}` accepted SSRF-style URL `{ssrf_url}` "
                            "without rejecting it."
                        ),
                        evidence=ssrf_url,
                        location=location,
                        source="dynamic",
                        confidence=0.55,
                    )
                )

    if case.payload_category == "prompt-injection":
        if _detect_prompt_reflection(text, payload_value) and not is_error:
            result.detected_signals.append("prompt-injection-reflected")
            result.findings.append(
                make_finding(
                    "MCPG028",
                    description=(
                        f"Tool `{case.tool_name}` reflected an attacker prompt "
                        "verbatim without wrapping it as untrusted output."
                    ),
                    evidence=text[:200],
                    location=location,
                    source="dynamic",
                    confidence=0.6,
                )
            )

    if case.payload_category == "oversize-input":
        if _TIMEOUT_MARKER in text or result.error == "timeout":
            result.detected_signals.append("oversize-timeout")
            result.findings.append(
                make_finding(
                    "MCPG029",
                    description=(
                        f"Tool `{case.tool_name}` hung or timed out on a large input."
                    ),
                    evidence=str(result.error or text[:200]),
                    location=location,
                    source="dynamic",
                    confidence=0.85,
                )
            )

    if case.payload_category in {"type-confusion", "extra-property", "missing-required"}:
        if not is_error and result.response_ok is True:
            result.detected_signals.append(f"{case.payload_category}-accepted")
            result.findings.append(
                make_finding(
                    "MCPG030",
                    description=(
                        f"Tool `{case.tool_name}` accepted input violating its "
                        f"schema ({case.payload_category})."
                    ),
                    evidence=str(case.arguments)[:200],
                    location=location,
                    source="dynamic",
                    confidence=0.6,
                )
            )

    # Universal post-checks (secret-shaped output, stack traces, abs paths).
    leaked = _detect_real_secret(text)
    if leaked:
        result.detected_signals.append("secret-pattern-in-output")
        result.findings.append(
            make_finding(
                "MCPG031",
                description=(
                    f"Tool `{case.tool_name}` returned content matching known secret patterns: "
                    + ", ".join(leaked[:3])
                ),
                evidence=", ".join(leaked[:3]),
                location=location,
                source="dynamic",
                confidence=0.9,
            )
        )

    stack = _detect_stack_trace(text)
    if stack:
        result.detected_signals.append("stack-trace-in-output")
        result.findings.append(
            make_finding(
                "MCPG032",
                description=f"Tool `{case.tool_name}` leaked a stack trace.",
                evidence=stack,
                location=location,
                source="dynamic",
                confidence=0.8,
            )
        )
    elif (abs_path := _detect_abs_path(text)) and is_error:
        result.detected_signals.append("absolute-path-in-output")
        result.findings.append(
            make_finding(
                "MCPG032",
                description=f"Tool `{case.tool_name}` leaked an absolute host path.",
                evidence=abs_path,
                location=location,
                source="dynamic",
                confidence=0.55,
            )
        )

    if result.error == "timeout" and case.payload_category != "oversize-input":
        result.detected_signals.append("tools-call-timeout")
        result.findings.append(
            make_finding(
                "MCPG035",
                description=(
                    f"Tool `{case.tool_name}` failed to respond within the "
                    "configured timeout."
                ),
                evidence=str(result.error),
                location=location,
                source="dynamic",
                confidence=0.7,
            )
        )


__all__ = ["inspect_fuzz_result"]


def attach_findings(results: list[FuzzResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        inspect_fuzz_result(r)
        out.extend(r.findings)
    return out
