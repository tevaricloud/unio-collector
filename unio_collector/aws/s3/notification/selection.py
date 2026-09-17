from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3.notification.summary import S3NotificationScanSummary


@dataclass(frozen=True)
class S3NotificationBucketSelection:  # noqa: D101
    buckets: list[dict[str, object]]
    summary: S3NotificationScanSummary
