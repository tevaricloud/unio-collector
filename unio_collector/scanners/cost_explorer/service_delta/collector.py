from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cost_explorer.service_delta.evidence import (
    CostExplorerServiceDeltaEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CostExplorerServiceDeltaCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> object:  # noqa: D102
        return CostExplorerServiceDeltaEvidence.capture(
            context.costs.collect_service_costs(),
            context.options.get_config(),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CostExplorerServiceDeltaScanner",
            implementation_module="unio_collector.scanners.cost_explorer.service_delta.scanner",
        )
