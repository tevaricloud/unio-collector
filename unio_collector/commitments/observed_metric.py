"""AWS-observed commitment metric contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime  # noqa: TC003
from decimal import Decimal  # noqa: TC003

from unio_collector.commitments.types import CommitmentValueNature  # noqa: TC001


@dataclass(frozen=True)
class ObservedCommitmentMetric:
    """Represent one AWS commitment metric with exact provenance."""

    service: str
    name: str
    value: Decimal | None
    unit: str
    source_operation: str
    source_field: str
    nature: CommitmentValueNature
    evidence_timestamp: datetime | None = None
    period_start: date | None = None
    period_end_exclusive: date | None = None
    currency: str | None = None
    source_id: str | None = None
    dimensions: tuple[tuple[str, str], ...] = ()
    limitations: tuple[str, ...] = ()


__all__ = ["ObservedCommitmentMetric"]
