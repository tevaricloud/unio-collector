"""Neutral scanner execution status, diagnostics, and metadata serialization."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from unio_collector.scanners.registry.catalog import get_scanner

ScannerStatus = Literal[
    "completed",
    "completed_with_warnings",
    "skipped",
    "disabled",
    "failed",
    "permission_denied",
    "unavailable",
]


@dataclass(init=False)
class ScannerExecutionResult:  # noqa: D101
    scanner_id: str
    status: ScannerStatus
    display_name: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    regions_scanned: list[str] = field(default_factory=list)
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    required_iam_actions: list[str] = field(default_factory=list)
    conditional_iam_actions: list[str] = field(default_factory=list)
    required_permission_level: str | None = None
    aws_api_calls: list[str] = field(default_factory=list)
    api_calls_attempted: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    coverage_notes: list[dict[str, Any]] = field(default_factory=list)
    reason: str | None = None
    skip_reason: str | None = None
    disabled_reason: str | None = None
    duration_ms: int | None = None
    evidence_count: int = 0
    api_call_count: int = 0
    implementation_type: str | None = None
    implementation_class: str | None = None
    implementation_module: str | None = None

    def __init__(  # noqa: D107
        self,
        *,
        scanner_id: str,
        status: ScannerStatus,
        display_name: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        regions_scanned: list[str] | None = None,
        findings_count: int = 0,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        required_iam_actions: list[str] | None = None,
        conditional_iam_actions: list[str] | None = None,
        required_permission_level: str | None = None,
        aws_api_calls: list[str] | None = None,
        api_calls_attempted: list[str] | None = None,
        limitations: list[str] | None = None,
        coverage_notes: list[dict[str, Any]] | None = None,
        reason: str | None = None,
        skip_reason: str | None = None,
        disabled_reason: str | None = None,
        duration_ms: int | None = None,
        evidence_count: int = 0,
        api_call_count: int = 0,
        implementation_type: str | None = None,
        implementation_class: str | None = None,
        implementation_module: str | None = None,
    ) -> None:
        self.scanner_id = scanner_id
        self.display_name = display_name
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.regions_scanned = list(regions_scanned or [])
        self.findings_count = findings_count
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])
        self.required_iam_actions = list(required_iam_actions or [])
        self.conditional_iam_actions = list(conditional_iam_actions or [])
        self.required_permission_level = required_permission_level
        self.aws_api_calls = list(aws_api_calls or [])
        self.api_calls_attempted = list(api_calls_attempted or [])
        self.limitations = list(limitations or [])
        self.coverage_notes = list(coverage_notes or [])
        resolved_reason = reason or skip_reason or disabled_reason
        self.reason = resolved_reason
        self.skip_reason = skip_reason or (resolved_reason if status == "skipped" else None)
        self.disabled_reason = disabled_reason or (resolved_reason if status == "disabled" else None)
        self.duration_ms = duration_ms
        self.evidence_count = evidence_count
        self.api_call_count = api_call_count
        self.implementation_type = implementation_type
        self.implementation_class = implementation_class
        self.implementation_module = implementation_module

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        raw = asdict(self)
        if not raw.get("display_name"):
            raw["display_name"] = get_scanner_display_name(self.scanner_id)
        raw["started_at"] = self.started_at.isoformat() if self.started_at else None
        raw["completed_at"] = self.completed_at.isoformat() if self.completed_at else None
        if raw["duration_ms"] is None and self.started_at and self.completed_at:
            raw["duration_ms"] = int(
                (self.completed_at - self.started_at).total_seconds() * 1000,
            )
        return raw


def disabled_execution_result(  # noqa: D103
    scanner_id: str,
    *,
    disabled_reason: str | None = None,
    coverage_notes: list[dict[str, Any]] | None = None,
) -> ScannerExecutionResult:
    definition = get_scanner(scanner_id)
    now = datetime.now(UTC)
    limitations = list(definition.limitations)
    if disabled_reason:
        limitations = [disabled_reason, *limitations]
    return ScannerExecutionResult(
        scanner_id=scanner_id,
        display_name=definition.display_name,
        status="disabled",
        started_at=now,
        completed_at=now,
        required_iam_actions=list(definition.required_iam_actions),
        conditional_iam_actions=list(definition.conditional_iam_actions),
        required_permission_level=definition.required_permission_level,
        aws_api_calls=list(definition.aws_api_calls),
        limitations=limitations,
        coverage_notes=coverage_notes,
        reason=disabled_reason or "Scanner was disabled for this run.",
        disabled_reason=disabled_reason or "Scanner was disabled for this run.",
        duration_ms=0,
        api_call_count=0,
        implementation_type="not_run",
    )


def get_scanner_display_name(scanner_id: str) -> str:  # noqa: D103
    try:
        return get_scanner(scanner_id).display_name
    except ValueError:
        return scanner_id.replace("-", " ").title()
