from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Literal

AnalysisReferenceTimeSource = Literal[
    "scanner_started_at",
    "legacy_manifest_evidence_generated_at",
    "legacy_bundle_generated_at",
]


@dataclass(frozen=True)
class AnalysisReferenceTime:
    """Stable instant used by scanner analysis and its replay."""

    instant: datetime
    source: AnalysisReferenceTimeSource

    def __post_init__(self) -> None:
        """Normalize the retained instant to UTC and reject naive values."""
        if self.instant.tzinfo is None:
            msg = "Scanner analysis reference time must include a timezone."
            raise ValueError(msg)
        object.__setattr__(self, "instant", self.instant.astimezone(UTC))

    @property
    def date(self) -> date:
        """Return the UTC calendar date for date-based scanner policy."""
        return self.instant.date()
