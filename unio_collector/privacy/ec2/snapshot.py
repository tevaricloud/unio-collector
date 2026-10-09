"""Closed actual-producer contract for snapshot age and retention evidence."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "metadata.older_than_days": ("integer", "safe_metadata", False),
    "records[].snapshot_id": ("string", "resource_id", False),
    "records[].volume_id": ("string", "resource_id", True),
    "records[].volume_size_gib": ("count", "safe_metadata", True),
    "records[].start_time": ("timestamp", "timestamp", True),
    "records[].age_days": ("count", "safe_metadata", False),
    "records[].description": ("string", "free_text", True),
}


class SnapshotPrivacyContract(Ec2PrivacyContract):
    """Preserve numeric retention policy while protecting identifiers and customer text."""

    scanner_id: ClassVar[str] = "snapshot-age-review"
    fixture_type: ClassVar[str] = "SnapshotFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Allow signed configured thresholds while keeping observations nonnegative."""
        if kind == "integer":
            return type(value) is int
        return super()._valid(value, kind, nullable=nullable)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Tokenise the entire arbitrary snapshot description in either profile."""
        decision = super().resolve(path, profile)
        if decision is not None and path == PREFIX + ".records[].description":
            return replace(decision, treatment="tokenise", reason="Customer-controlled snapshot description is protected as a whole value.")
        return decision
