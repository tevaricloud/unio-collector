from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import (
        ScannerNetworkGatewayRuntime,
    )


@dataclass(frozen=True)
class ScannerNetworkGateway:  # noqa: D101
    runtime: ScannerNetworkGatewayRuntime
    definition: ScannerDefinition

    def collect_items_by_region(  # noqa: D102
        self,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> dict[str, list[dict[str, Any]]]:
        return self.runtime.collect_cached_network_items_by_region(
            self.definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def collect_batch(  # noqa: D102
        self,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> NetworkInventoryBatch:
        return self.runtime.collect_cached_network_batch(
            self.definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def get_regions(self) -> list[str]:  # noqa: D102
        return self.runtime.get_cached_network_regions(self.definition)

    def collect_nat_gateway_records(self) -> list[Any]:  # noqa: D102
        return self.runtime.collect_cached_network_nat_gateway_records(self.definition)

    def create_collector(self, *, regions: list[str] | None = None) -> Any:  # noqa: ANN401, D102
        return self.runtime.create_network_collector(self.definition, regions=regions)
