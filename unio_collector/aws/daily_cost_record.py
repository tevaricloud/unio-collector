from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import date
    from decimal import Decimal


@dataclass(frozen=True)
class DailyCostRecord:  # noqa: D101
    date: date
    service_name: str
    region: str
    usage_type: str | None
    cost: Decimal
    currency: str
