from __future__ import annotations  # noqa: D100

from typing import TypeVar

from unio_collector.aws.s3 import (
    S3BucketLifecycleRecord,
    S3MultipartUploadRecord,
)

S3_COST_EXPLORER_SERVICE_NAMES = ("Amazon Simple Storage Service",)

TS3CostRecord = TypeVar(
    "TS3CostRecord",
    S3BucketLifecycleRecord,
    S3MultipartUploadRecord,
)
