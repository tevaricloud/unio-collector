from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.aws.network.inventory import NetworkInventoryCollector
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerNetworkGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner network gateways."""

    def collect_cached_network_items_by_region(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [NetworkInventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> dict[str, list[dict[str, Any]]]: ...

    def collect_cached_network_batch(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [NetworkInventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> NetworkInventoryBatch: ...

    def get_cached_network_regions(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[str]: ...

    def collect_cached_network_nat_gateway_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[NatGatewayRecord]: ...

    def create_network_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector: ...
