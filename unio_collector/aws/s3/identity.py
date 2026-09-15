from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class S3BucketIdentity:  # noqa: D101
    bucket_name: str
    account_id: str
    region: str
    arn: str
    creation_date: datetime | None
    warning: str | None = None
