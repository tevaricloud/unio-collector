from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from unio_collector.aws.rds.helpers import (
    age_in_days,
    get_optional_int,
    get_optional_string,
)
from unio_collector.aws.rds.snapshot.candidate import RdsSnapshotCandidate


@dataclass(frozen=True)
class RdsSnapshotCollectionPlan:  # noqa: D101
    operation_name: str
    result_key: str
    arn_key: str
    identifier_key: str
    source_identifier_key: str
    snapshot_kind: str

    def build_request_parameters(self) -> dict[str, Any]:  # noqa: D102
        return {
            "SnapshotType": "manual",
            "MaxRecords": 100,
        }

    def build_candidate(  # noqa: D102
        self,
        *,
        snapshot: dict[str, Any],
        region: str,
        now: datetime,
    ) -> RdsSnapshotCandidate | None:
        created_at = snapshot.get("SnapshotCreateTime")
        age_days = age_in_days(created_at, now)
        if age_days is None:
            return None
        return RdsSnapshotCandidate(
            snapshot_identifier=(get_optional_string(snapshot, self.identifier_key) or "unknown"),
            snapshot_arn=get_optional_string(snapshot, self.arn_key),
            source_identifier=get_optional_string(
                snapshot,
                self.source_identifier_key,
            ),
            region=region,
            snapshot_kind=self.snapshot_kind,
            snapshot_type=get_optional_string(snapshot, "SnapshotType") or "manual",
            engine=get_optional_string(snapshot, "Engine"),
            status=get_optional_string(snapshot, "Status"),
            storage_gib=get_optional_int(snapshot, "AllocatedStorage"),
            created_at=created_at if isinstance(created_at, datetime) else None,
            age_days=age_days,
        )


RDS_DB_SNAPSHOT_PLAN = RdsSnapshotCollectionPlan(
    operation_name="describe_db_snapshots",
    result_key="DBSnapshots",
    arn_key="DBSnapshotArn",
    identifier_key="DBSnapshotIdentifier",
    source_identifier_key="DBInstanceIdentifier",
    snapshot_kind="db_instance_snapshot",
)
RDS_CLUSTER_SNAPSHOT_PLAN = RdsSnapshotCollectionPlan(
    operation_name="describe_db_cluster_snapshots",
    result_key="DBClusterSnapshots",
    arn_key="DBClusterSnapshotArn",
    identifier_key="DBClusterSnapshotIdentifier",
    source_identifier_key="DBClusterIdentifier",
    snapshot_kind="db_cluster_snapshot",
)
