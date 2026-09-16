from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class ServiceCostContext:  # noqa: D101
    current_cost: Decimal | None = None
    previous_cost: Decimal | None = None
    currency: str | None = None
