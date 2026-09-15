from __future__ import annotations

# ruff: noqa: D100
from dataclasses import dataclass


@dataclass(frozen=True)
class RoleAssumptionAuditRecord:
    """Persist safe role-assumption metadata without credential material."""

    account_reference: str
    role_arn: str
    duration_seconds: int
    external_id_present: bool
    external_id_source_kind: str | None
    request_id: str | None
    outcome: str
    failure_category: str | None = None
