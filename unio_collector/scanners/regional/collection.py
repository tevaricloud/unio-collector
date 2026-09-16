from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.inventory_evidence import InventoryEvidence

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class RegionalInventoryCollector(BaseUnioScanner):
    """Share evidence collection without private scanner analysis."""

    collector_id: str

    collector_type: type[Any]

    def collect(self, context: ScannerContext) -> InventoryEvidence:  # noqa: D102
        collector = self.create_collector(context)
        return InventoryEvidence(
            records=self.collect_inventory_records(collector, context),
            regions=self.collect_inventory_regions(collector, context),
            metadata=self.collect_inventory_metadata(collector, context),
        )

    def create_collector(self, context: ScannerContext) -> Any:  # noqa: ANN401, D102
        return context.security.create_regional_inventory_collector(
            self.collector_type,
            collector_name=self.collector_id,
        )

    def collect_inventory_records(  # noqa: D102
        self,
        collector: Any,  # noqa: ANN401
        context: ScannerContext,
    ) -> list[Any]:
        raise NotImplementedError

    def collect_inventory_regions(  # noqa: D102
        self,
        collector: Any,  # noqa: ANN401
        context: ScannerContext,
    ) -> list[str]:
        del context
        return [str(region) for region in collector.get_available_regions()]

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: Any,  # noqa: ANN401
        context: ScannerContext,
    ) -> dict[str, Any]:
        del collector, context
        return {}
