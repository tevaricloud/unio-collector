from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import date


@dataclass(frozen=True)
class CostExplorerRequestFactory:
    """Build Cost Explorer request payloads for supported scan queries."""

    metric_name: str = "UnblendedCost"

    def build_daily_request(  # noqa: D102
        self,
        *,
        start: date,
        end_exclusive: date,
        group_keys: tuple[str, ...],
    ) -> dict[str, Any]:
        return {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end_exclusive.isoformat(),
            },
            "Granularity": "DAILY",
            "Metrics": [self.metric_name],
            "GroupBy": [{"Type": "DIMENSION", "Key": key} for key in group_keys],
        }

    def build_service_request(  # noqa: D102
        self,
        *,
        start: date,
        end_exclusive: date,
    ) -> dict[str, Any]:
        return self.build_daily_request(
            start=start,
            end_exclusive=end_exclusive,
            group_keys=("SERVICE",),
        )

    def build_monthly_total_request(  # noqa: D102
        self,
        *,
        start: date,
        end_exclusive: date,
    ) -> dict[str, Any]:
        return {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end_exclusive.isoformat(),
            },
            "Granularity": "MONTHLY",
            "Metrics": [self.metric_name],
        }
