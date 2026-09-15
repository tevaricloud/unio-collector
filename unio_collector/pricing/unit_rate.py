from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class UnitRate:  # noqa: D101
    amount: Decimal
    currency: str
    unit: str
    source: str
