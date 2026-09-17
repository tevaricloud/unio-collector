from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal

CollectionCoverageStatus = Literal["collected", "unavailable", "not_applicable", "legacy_unknown"]


@dataclass(frozen=True)
class OriginProtectionCoverageRecord:
    """Collection completeness for one origin-protection evidence scope."""

    scope_id: str
    evidence_type: str
    status: CollectionCoverageStatus
    evidence_ref: str = ""
    limitation: str = ""
