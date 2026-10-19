"""Bind current commitment evidence to its registered collector identity."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.commitment.base import CommitmentPrivacyBase
from unio_collector.privacy.commitment.dimension import CommitmentDimensionContract
from unio_collector.privacy.commitment.fields import DIMENSION
from unio_collector.privacy.commitment.location import CommitmentLocationDimensionContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


class CommitmentPrivacyContract(CommitmentPrivacyBase):
    """Keep legacy replay untouched; current producer lists are deliberately empty and closed."""

    scanner_id: ClassVar[str] = "commitment-and-pricing-review"
    identities: ClassVar = {scanner_id: ("cost_explorer.commitment.evidence", "CommitmentReviewEvidence", {})}

    def for_sequence(self, value: list[Any], path: str) -> ClosedProducerContract | None:
        """Bind only admitted two-string dimension pairs, leaving all other arrays unchanged."""
        if path.removeprefix(self.prefix + ".") != DIMENSION or not self._valid(value, "pair", nullable=False):
            return None
        cls = CommitmentLocationDimensionContract if value[0] in {"region", "REGION", "availabilityZone", "AZ"} else CommitmentDimensionContract
        return cls(value[0])
