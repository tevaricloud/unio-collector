from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.formatting import (
    calculate_percentage,
    format_decimal_for_json,
)

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class FreeTierUsageRecord:  # noqa: D101
    service: str
    operation: str
    usage_type: str
    region: str
    actual_usage_amount: Decimal | None
    forecasted_usage_amount: Decimal | None
    limit: Decimal | None
    unit: str
    description: str
    free_tier_type: str

    def get_utilization_percent(self) -> Decimal | None:  # noqa: D102
        return calculate_percentage(self.actual_usage_amount, self.limit)

    def get_forecast_percent(self) -> Decimal | None:  # noqa: D102
        return calculate_percentage(self.forecasted_usage_amount, self.limit)

    def get_remaining_amount(self) -> Decimal | None:  # noqa: D102
        if self.actual_usage_amount is None or self.limit is None:
            return None
        return self.limit - self.actual_usage_amount

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "service": self.service,
            "operation": self.operation,
            "usage_type": self.usage_type,
            "region": self.region,
            "actual_usage_amount": format_decimal_for_json(self.actual_usage_amount),
            "forecasted_usage_amount": format_decimal_for_json(
                self.forecasted_usage_amount,
            ),
            "limit": format_decimal_for_json(self.limit),
            "remaining_amount": format_decimal_for_json(self.get_remaining_amount()),
            "utilization_percent": format_decimal_for_json(
                self.get_utilization_percent(),
            ),
            "forecast_percent": format_decimal_for_json(self.get_forecast_percent()),
            "unit": self.unit,
            "description": self.description,
            "free_tier_type": self.free_tier_type,
        }
