from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.aws.rds.snapshot.record import RdsSnapshotRecord

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class RdsSnapshotCandidate:  # noqa: D101
    snapshot_identifier: str
    snapshot_arn: str | None
    source_identifier: str | None
    region: str
    snapshot_kind: str
    snapshot_type: str
    engine: str | None
    status: str | None
    storage_gib: int | None
    created_at: datetime | None
    age_days: int

    def convert_to_record(  # noqa: D102
        self,
        account_id: str,
        tags_by_arn: dict[str, dict[str, str]],
    ) -> RdsSnapshotRecord:
        return RdsSnapshotRecord(
            snapshot_identifier=self.snapshot_identifier,
            snapshot_arn=self.snapshot_arn,
            source_identifier=self.source_identifier,
            account_id=account_id,
            region=self.region,
            snapshot_kind=self.snapshot_kind,
            snapshot_type=self.snapshot_type,
            engine=self.engine,
            status=self.status,
            storage_gib=self.storage_gib,
            created_at=self.created_at,
            age_days=self.age_days,
            tags=tags_by_arn.get(str(self.snapshot_arn or ""), {}),
        )
