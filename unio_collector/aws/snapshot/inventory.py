from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.inventory_helpers import AwsInventoryTagHelper
from unio_collector.aws.snapshot.collector import (
    SnapshotInventoryCollector,
    snapshot_age_days,
)
from unio_collector.aws.snapshot.record import SnapshotRecord

_TAG_HELPER = AwsInventoryTagHelper()


def tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return _TAG_HELPER.tags_to_dict(tags)


__all__ = [
    "SnapshotInventoryCollector",
    "SnapshotRecord",
    "snapshot_age_days",
    "tags_to_dict",
]
