from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.core.scan.period import ScanPeriod


@dataclass(frozen=True)
class CostExplorerEvidenceCacheKeyBuilder:
    """Builds stable cache keys for shared Cost Explorer evidence."""

    account_id: str

    def build_service_costs_key(  # noqa: D102
        self,
        *,
        period: ScanPeriod,
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            period.current_start_date.isoformat(),
            period.current_end_exclusive.isoformat(),
            period.previous_start_date.isoformat(),
            period.previous_end_exclusive.isoformat(),
        )

    def build_daily_costs_key(  # noqa: D102
        self,
        *,
        period: ScanPeriod,
        group_keys: tuple[str, ...],
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            period.current_start_date.isoformat(),
            period.current_end_exclusive.isoformat(),
            group_keys,
        )
