from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING

from unio_collector.core.cost_period import CostPeriod

if TYPE_CHECKING:
    from unio_collector.collector.config.protocol import CollectionConfigProtocol


def default_cost_periods(config: CollectionConfigProtocol) -> tuple[CostPeriod, CostPeriod]:  # noqa: D103
    current_start = config.scan_period.current_start_date
    current_end = config.scan_period.current_end_date
    previous_start = config.scan_period.previous_start_date
    previous_end = config.scan_period.previous_end_date
    currency = config.default_currency
    return (
        CostPeriod(
            start_date=previous_start,
            end_date=previous_end,
            total_cost=Decimal(0),
            currency=currency,
        ),
        CostPeriod(
            start_date=current_start,
            end_date=current_end,
            total_cost=Decimal(0),
            currency=currency,
        ),
    )
