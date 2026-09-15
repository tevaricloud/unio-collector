from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.platform_inventory import ApiGatewayRegionRecord


@dataclass(frozen=True)
class ApiGatewayCostReviewEvidence:  # noqa: D101
    records: list[ApiGatewayRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
