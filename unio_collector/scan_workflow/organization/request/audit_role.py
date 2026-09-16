from __future__ import annotations

# ruff: noqa: D100,TC001
from dataclasses import dataclass

from unio_collector.scan_workflow.organization.request.external_id import ExternalIdReference


@dataclass(frozen=True)
class AuditRoleConfiguration:
    """Configure a bounded cross-account audit session."""

    role_name: str | None
    arn_template: str | None
    session_name_prefix: str
    duration_seconds: int
    external_id: ExternalIdReference | None = None
