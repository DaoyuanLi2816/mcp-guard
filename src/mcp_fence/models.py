"""Pydantic models that describe scan results, findings, MCP inventories,
fuzz cases, and aggregate report payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 4,
            Severity.HIGH: 7,
            Severity.CRITICAL: 10,
        }[self]

    @property
    def sarif_level(self) -> str:
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]


class Location(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target: str | None = None
    path: str | None = None
    line: int | None = None
    tool: str | None = None
    parameter: str | None = None
    pointer: str | None = None  # JSON pointer or schema path

    def short(self) -> str:
        parts: list[str] = []
        if self.path:
            parts.append(self.path + (f":{self.line}" if self.line else ""))
        if self.tool:
            parts.append(f"tool={self.tool}")
        if self.parameter:
            parts.append(f"param={self.parameter}")
        if self.pointer:
            parts.append(self.pointer)
        if not parts and self.target:
            parts.append(self.target)
        return " ".join(parts) if parts else "(unknown)"


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_id: str
    severity: Severity
    category: str
    title: str
    description: str
    evidence: str | None = None
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    location: Location = Field(default_factory=Location)
    source: str = "static"  # static | metadata | schema | dynamic | llm-judge


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)


class ServerInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    version: str | None = None


class Inventory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target: str
    transport: str = "stdio"
    command: list[str] | None = None
    env_keys: list[str] = Field(default_factory=list)
    server_info: ServerInfo = Field(default_factory=ServerInfo)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    protocol_version: str | None = None
    tools: list[ToolSpec] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class FuzzCase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    case_id: str
    tool_name: str
    payload_category: str
    intent: str
    arguments: dict[str, Any]
    is_unsafe: bool = False  # whether this payload requires --allow-unsafe / sandbox


class FuzzResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    case: FuzzCase
    skipped: bool = False
    skip_reason: str | None = None
    response_ok: bool | None = None
    response_text: str = ""
    response_data: Any | None = None
    error: str | None = None
    duration_ms: int = 0
    detected_signals: list[str] = Field(default_factory=list)
    boundary_violation: bool = False
    findings: list[Finding] = Field(default_factory=list)


class Summary(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    score: int = 0
    verdict: str = "PASS"


class ScanResult(BaseModel):
    """Top-level payload that the CLI emits as JSON and that the report
    renderers consume."""

    model_config = ConfigDict(extra="ignore")
    schema_version: str = "1.0"
    tool: str = "mcp-fence"
    tool_version: str = "0.1.0"
    target: str
    kind: str = "scan"  # scan | inspect | fuzz
    started_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    completed_at: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    inventory: Inventory | None = None
    fuzz_results: list[FuzzResult] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)
    notes: list[str] = Field(default_factory=list)

    def compute_summary(self) -> Summary:
        """Recompute summary, score, and verdict from current findings."""
        all_findings = list(self.findings)
        for fr in self.fuzz_results:
            all_findings.extend(fr.findings)

        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        score = 0
        category_cap: dict[str, int] = {}
        for f in all_findings:
            sev = f.severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            weighted = f.severity.weight
            # Cap each category to avoid one noisy category dominating the score.
            cap_left = 25 - category_cap.get(f.category, 0)
            if cap_left <= 0:
                continue
            inc = min(weighted, cap_left)
            score += inc
            category_cap[f.category] = category_cap.get(f.category, 0) + inc
        score = min(100, score)

        verdict = "PASS"
        if by_sev.get("high", 0) > 0 or by_sev.get("critical", 0) > 0:
            verdict = "FAIL"
        elif by_sev.get("medium", 0) > 0 or by_sev.get("low", 0) > 0:
            verdict = "WARN"

        self.summary = Summary(
            total=len(all_findings),
            by_severity=by_sev,
            by_category=by_cat,
            score=score,
            verdict=verdict,
        )
        return self.summary

    def finalize(self) -> None:
        self.completed_at = datetime.now(UTC).isoformat()
        self.compute_summary()


class SandboxPlan(BaseModel):
    """Output of `mcp-fence sandbox`."""

    model_config = ConfigDict(extra="ignore")
    target: str
    profile: str
    image: str
    command_args: list[str]
    docker_argv: list[str]
    docker_command: str
    compose_fragment: str
    notes: list[str] = Field(default_factory=list)
    docker_available: bool = True
