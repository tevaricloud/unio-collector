from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cost_explorer.daily_evidence import DailyCostEvidence

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CachedDailyCostCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    group_keys: tuple[str, ...] = ("SERVICE",)

    def collect(self, context: ScannerContext) -> DailyCostEvidence:  # noqa: D102
        return DailyCostEvidence(
            records=context.costs.collect_daily_costs(group_keys=self.group_keys),
            scan_period=context.options.get_scan_period(),
        )
