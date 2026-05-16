"""Execute a fuzz corpus against a running MCP server."""

from __future__ import annotations

import enum
import time
from typing import Iterable

from ..constants import DEFAULT_TIMEOUTS
from ..mcp.client import McpStdioClient, connect_stdio
from ..mcp.inventory import ServerSpec
from ..mcp.protocol import parse_error, parse_tool_result_text
from ..mcp.stdio_client import StdioTimeout, StdioTransportError
from ..models import FuzzCase, FuzzResult, Inventory
from ..scanner.metadata_scan import collect_high_risk_tools
from ..utils.logging import get_logger

log = get_logger()


class RunMode(str, enum.Enum):
    SAFE = "safe"
    TOY = "toy"
    ALLOW_UNSAFE = "allow-unsafe"


def _gate_case(case: FuzzCase, inventory: Inventory, mode: RunMode) -> tuple[bool, str | None]:
    """Decide whether to run *case* in the current mode."""
    if mode in {RunMode.TOY, RunMode.ALLOW_UNSAFE}:
        return True, None
    # SAFE mode: skip clearly destructive categories against high-risk tools.
    high_risk = collect_high_risk_tools(inventory)
    if case.is_unsafe:
        if case.tool_name in high_risk:
            return (
                False,
                "safe-mode: refuses to execute command-injection payloads against "
                "high-risk tool; rerun with --toy-mode or --allow-unsafe, or use "
                "`mcp-guard sandbox`",
            )
    return True, None


def _run_single(
    client: McpStdioClient,
    case: FuzzCase,
    *,
    call_timeout: float,
) -> FuzzResult:
    start = time.monotonic()
    result = FuzzResult(case=case)
    try:
        resp = client.tools_call(case.tool_name, case.arguments, timeout=call_timeout)
        duration_ms = int((time.monotonic() - start) * 1000)
        result.duration_ms = duration_ms
        err = parse_error(resp)
        if err is not None:
            result.response_ok = False
            result.error = err
            return result
        raw_result = resp.get("result") if isinstance(resp, dict) else None
        result.response_data = raw_result
        result.response_text = parse_tool_result_text(raw_result)
        result.response_ok = not (isinstance(raw_result, dict) and raw_result.get("isError"))
    except StdioTimeout:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        result.error = "timeout"
        result.response_ok = False
    except StdioTransportError as e:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        result.error = f"transport-error: {e}"
        result.response_ok = False
    return result


def run_fuzz(
    spec: ServerSpec,
    inventory: Inventory,
    cases: Iterable[FuzzCase],
    *,
    mode: RunMode = RunMode.SAFE,
    call_timeout: float = DEFAULT_TIMEOUTS["tools_call"],
    oversize_timeout: float = DEFAULT_TIMEOUTS["oversize_call"],
    max_cases: int | None = None,
) -> list[FuzzResult]:
    """Drive a freshly-spawned MCP server through *cases*.

    Each call uses ``call_timeout``; oversize cases use ``oversize_timeout``.
    """
    case_list = list(cases)
    if max_cases is not None:
        case_list = case_list[:max_cases]
    if not case_list:
        return []
    if spec.transport != "stdio" or not spec.argv:
        return [
            FuzzResult(
                case=c,
                skipped=True,
                skip_reason="fuzz currently supports stdio transport only",
            )
            for c in case_list
        ]

    results: list[FuzzResult] = []
    client: McpStdioClient | None = None
    try:
        client = connect_stdio(
            spec.argv,
            cwd=spec.cwd,
            env=spec.env,
            default_timeout=call_timeout,
        )
        try:
            client.initialize(timeout=DEFAULT_TIMEOUTS["initialize"])
        except Exception as e:
            log.warning("initialize failed during fuzz: %s", e)
            for c in case_list:
                results.append(
                    FuzzResult(case=c, skipped=True, skip_reason=f"initialize failed: {e}")
                )
            return results

        for case in case_list:
            allowed, reason = _gate_case(case, inventory, mode)
            if not allowed:
                results.append(
                    FuzzResult(case=case, skipped=True, skip_reason=reason)
                )
                continue
            timeout = oversize_timeout if case.payload_category == "oversize-input" else call_timeout
            r = _run_single(client, case, call_timeout=timeout)
            results.append(r)
    except Exception as e:
        log.error("fuzz runner crashed: %s", e)
        if not results:
            results = [
                FuzzResult(case=c, skipped=True, skip_reason=f"runner error: {e}")
                for c in case_list
            ]
    finally:
        if client is not None:
            client.close()

    return results
