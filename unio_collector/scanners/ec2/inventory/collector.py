from __future__ import annotations  # noqa: D100

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.inventory_evidence import InventoryEvidence

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scanners.scanner.context import ScannerContext


class CachedEc2InventoryCollector(BaseUnioScanner, ABC):
    """Share evidence collection without private scanner analysis."""

    collection_name: str

    def collect(self, context: ScannerContext) -> InventoryEvidence:  # noqa: D102
        return InventoryEvidence(
            records=context.ec2.collect_records(
                collection_name=self.collection_name,
                collect_records=self.collect_records,
                period_key=self.get_period_key(context),
            ),
            regions=context.ec2.get_regions(),
        )

    def collect_cached_records(  # noqa: D102
        self,
        context: ScannerContext,
        *,
        collect_records: Callable[[Any], list[Any]],
    ) -> list[Any]:
        return context.ec2.collect_records(
            collection_name=self.collection_name,
            collect_records=collect_records,
            period_key=self.get_period_key(context),
        )

    def get_period_key(self, context: ScannerContext) -> str | None:  # noqa: D102
        del context
        return None

    @abstractmethod
    def collect_records(self, collector: Any) -> list[Any]: ...  # noqa: ANN401, D102
