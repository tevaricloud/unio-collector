from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class RegionalCostContext:  # noqa: D101
    current_cost: Decimal = Decimal(0)
    currency: str = "USD"
    record_count: int = 0
