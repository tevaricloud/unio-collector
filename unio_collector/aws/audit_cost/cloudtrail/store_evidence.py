"""Normalized CloudTrail Lake event-data-store evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.cloudtrail.selector_evidence import (
        CloudTrailSelectorEvidence,
    )


@dataclass(frozen=True)
class CloudTrailEventDataStoreEvidence:
    """Allowlisted provider facts for one CloudTrail Lake data store."""

    identifier: str = ""
    name: str | None = None
    status: str | None = None
    retention_period_days: int | None = None
    advanced_selectors: list[CloudTrailSelectorEvidence] = field(
        default_factory=list,
    )


__all__ = ["CloudTrailEventDataStoreEvidence"]
