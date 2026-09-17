from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PublicServiceExposureRecord:  # noqa: D101
    service_name: str
    region: str
    resource_type: str
    resource_id: str
    exposure_type: str
    confidence: str
    detail: str
    resource_name: str | None = None
    arn: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
