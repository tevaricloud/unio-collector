from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.ec2.ebs.encryption_region import EbsEncryptionRegionRecord
    from unio_collector.scanners.ec2.ebs.snapshot_encryption import (
        EbsSnapshotEncryptionRecord,
    )
    from unio_collector.scanners.ec2.ebs.volume_encryption import EbsVolumeEncryptionRecord
    from unio_collector.scanners.s3.encryption.bucket_record import S3BucketEncryptionRecord


@dataclass(frozen=True)
class EncryptionBaselineEvidence:  # noqa: D101
    ebs_region_settings: tuple[EbsEncryptionRegionRecord, ...] = ()
    ebs_volumes: tuple[EbsVolumeEncryptionRecord, ...] = ()
    ebs_snapshots: tuple[EbsSnapshotEncryptionRecord, ...] = ()
    s3_buckets: tuple[S3BucketEncryptionRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
