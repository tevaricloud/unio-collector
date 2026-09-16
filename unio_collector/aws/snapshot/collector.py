from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.aws.inventory_helpers import (
    AwsEc2RegionDiscoveryHelper,
    AwsInventoryTagHelper,
    AwsInventoryValueHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.snapshot.record import SnapshotRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext


class SnapshotInventoryCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._available_regions_cache: list[str] | None = None
        self._pagination = AwsPaginationHelper()
        self._regions = AwsEc2RegionDiscoveryHelper(
            self.session,
            audit_context=self.audit_context,
        )
        self._tags = AwsInventoryTagHelper()
        self._values = AwsInventoryValueHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="SnapshotInventoryCollector",
        )

    def collect_snapshots(self) -> list[SnapshotRecord]:  # noqa: D102
        now = datetime.now(UTC)
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="ec2",
            operation="DescribeSnapshots",
            collect_region=lambda region: self._collect_snapshots_in_region(
                region,
                now,
            ),
        )

    def _collect_snapshots_in_region(
        self,
        region: str,
        now: datetime,
    ) -> list[SnapshotRecord]:
        records: list[SnapshotRecord] = []
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "describe_snapshots",
            result_key="Snapshots",
            request_parameters={"OwnerIds": ["self"], "MaxResults": 1000},
        ).pages
        for snapshot in self._values.collect_dict_items(pages, "Snapshots"):
            start_time = snapshot.get("StartTime")
            age_days = snapshot_age_days(start_time, now)
            if age_days is None:
                continue
            records.append(
                SnapshotRecord(
                    snapshot_id=snapshot["SnapshotId"],
                    account_id=self.account_id,
                    region=region,
                    volume_id=snapshot.get("VolumeId"),
                    volume_size_gib=snapshot.get("VolumeSize"),
                    start_time=start_time,
                    age_days=age_days,
                    description=snapshot.get("Description"),
                    tags=self._tags.tags_to_dict(snapshot.get("Tags", [])),
                ),
            )
        return records

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        self._available_regions_cache = self._regions.get_available_regions(
            self.selected_regions,
        )
        return self._available_regions_cache


def snapshot_age_days(start_time: datetime | None, now: datetime) -> int | None:  # noqa: D103
    if start_time is None:
        return None
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC)
    return max((now - start_time).days, 0)
