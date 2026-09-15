from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.core.error.helpers import (
        AwsErrorCategory,
        ServiceAvailabilityStatus,
    )


@dataclass(frozen=True)
class AwsErrorClassification:  # noqa: D101
    code: str | None
    message: str
    category: AwsErrorCategory
    expected_absence: bool
    service_unavailable: bool
    permission_denied: bool
    throttling: bool
    unsupported_region: bool
    retryable: bool
    reason: str | None = None
    service_availability_status: ServiceAvailabilityStatus = "unknown"
