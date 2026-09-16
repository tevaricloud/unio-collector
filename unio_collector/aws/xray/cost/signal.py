from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class XRayCostSignal:  # noqa: D101
    service_name: str = "AWS X-Ray"
    previous_cost: Decimal = Decimal(0)
    current_cost: Decimal = Decimal(0)
    absolute_delta: Decimal = Decimal(0)
    currency: str = "USD"

    @property
    def has_cost_signal(self) -> bool:  # noqa: D102
        return self.current_cost > 0 or self.absolute_delta > 0
