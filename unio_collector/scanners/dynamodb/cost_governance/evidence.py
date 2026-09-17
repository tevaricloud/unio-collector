from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.dynamodb import DynamoDbRegionRecord


@dataclass(frozen=True)
class DynamoDbCostGovernanceEvidence:  # noqa: D101
    records: list[DynamoDbRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
