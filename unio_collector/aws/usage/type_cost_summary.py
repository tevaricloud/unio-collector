from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class UsageTypeCostSummary:  # noqa: D101
    usage_type: str
    current_cost: Decimal
    currency: str
    record_count: int = 0
