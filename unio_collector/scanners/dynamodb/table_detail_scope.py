from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord


@dataclass(frozen=True)
class DynamoDbTableDetailScope:  # noqa: D101
    mode: str
    attempted_regions: list[str]
    detail_regions: list[str]
    summary_regions: list[str] = field(default_factory=list)
    regional_costs: list[DailyCostRecord] = field(default_factory=list)
