from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class PeriodCosts:  # noqa: D101
    cost_by_service: dict[str, Decimal]
    currency: str | None
