"""Closed DB-instance and cluster snapshot inventory privacy."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.ec2.base import COMMON_FIELDS
from unio_collector.privacy.rds.base import RdsPrivacyContract

FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "metadata.older_than_days": ("count", "safe_metadata", False),
    "records[].snapshot_identifier": ("string", "resource_id", False),
    "records[].snapshot_arn": ("string", "arn", True),
    "records[].source_identifier": ("string", "resource_id", True),
    "records[].snapshot_kind": ("snapshot_kind", "safe_metadata", False),
    "records[].snapshot_type": ("string", "free_text", False),
    "records[].engine": ("string", "free_text", True),
    "records[].status": ("string", "free_text", True),
    "records[].storage_gib": ("count", "safe_metadata", True),
    "records[].created_at": ("timestamp", "timestamp", True),
    "records[].age_days": ("count", "safe_metadata", False),
}


class RdsSnapshotPrivacyContract(RdsPrivacyContract):
    """Protect names/tags, preserve numeric retention and generalise strict dates."""

    scanner_id: ClassVar[str] = "rds-snapshot-retention-review"
    fixture_type: ClassVar[str] = "RdsSnapshotFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "snapshot_kind":
            return value in {"db_instance_snapshot", "db_cluster_snapshot"} if isinstance(value, str) else False
        return super()._valid(value, kind, nullable=nullable)
