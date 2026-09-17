from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal


@dataclass(frozen=True)
class S3MultipartUploadRecord:  # noqa: D101
    bucket_name: str
    account_id: str
    region: str
    arn: str
    upload_count: int
    oldest_initiated: datetime | None = None
    sample_keys: list[str] = field(default_factory=list)
    page_count: int = 0
    pagination_complete: bool = True
    limitations: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
