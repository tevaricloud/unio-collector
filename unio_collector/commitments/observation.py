"""Observed commitment portfolio collected before private assessment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date  # noqa: TC003
from typing import Any, Literal

from unio_collector.commitments.inventory import CommitmentInventoryItem  # noqa: TC001
from unio_collector.commitments.observed_metric import ObservedCommitmentMetric  # noqa: TC001
from unio_collector.commitments.source import CommitmentSourceOutcome  # noqa: TC001
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload, require_serialized_scanner_evidence


@dataclass(frozen=True)
class ObservedCommitmentPortfolio:
    """Carry provider inventory, observed metrics, and collection limitations."""

    schema_version: Literal["2026-08"] = "2026-08"
    account_id: str = "unknown-account"
    period_start: date | None = None
    period_end_exclusive: date | None = None
    inventory: tuple[CommitmentInventoryItem, ...] = ()
    observed_metrics: tuple[ObservedCommitmentMetric, ...] = ()
    source_outcomes: tuple[CommitmentSourceOutcome, ...] = ()
    regions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject unsupported observed portfolio versions before replay."""
        if self.schema_version != "2026-08":
            message = "Unsupported commitment portfolio evidence version."
            raise ValueError(message)

    def convert_to_dict(self) -> dict[str, Any]:
        """Serialize observations using the shared finite evidence contract."""
        envelope = build_scanner_evidence_payload(scanner_id="commitment-and-pricing-review", evidence=self)
        require_serialized_scanner_evidence(envelope)
        return envelope["payload"]
