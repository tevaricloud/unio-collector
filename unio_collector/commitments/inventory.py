"""Composite commitment inventory record."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003

from unio_collector.commitments.identity import CommitmentIdentity  # noqa: TC001
from unio_collector.commitments.payment import CommitmentPayment  # noqa: TC001
from unio_collector.commitments.specification import CommitmentSpecification  # noqa: TC001
from unio_collector.commitments.term import CommitmentTerm  # noqa: TC001
from unio_collector.commitments.types import CommitmentValueNature


@dataclass(frozen=True)
class CommitmentInventoryItem:
    """Combine identity, applicability, term, and payment inventory evidence."""

    identity: CommitmentIdentity
    specification: CommitmentSpecification
    term: CommitmentTerm
    payment: CommitmentPayment
    source_operation: str | None = None
    evidence_timestamp: datetime | None = None
    nature: CommitmentValueNature = CommitmentValueNature.AWS_OBSERVED


__all__ = ["CommitmentInventoryItem"]
