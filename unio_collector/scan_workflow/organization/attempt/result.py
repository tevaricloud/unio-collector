"""Serializable result returned by an organization account child process."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OrganizationAttemptResult:
    """Describe staged artifacts that still require parent promotion."""

    account_reference: str
    bundle_sha256: str
    bundle_schema_version: str
    bundle_purpose: str
    degraded: bool
    role_audit: dict[str, object]
    report_relative_path: str | None = None
    report_failure_code: str | None = None
    finding_counts: dict[str, int] = field(default_factory=dict)
    analysis_state: str = "not_analyzed"


__all__ = ["OrganizationAttemptResult"]
