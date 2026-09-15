from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.ec2 import Ec2InventoryCollector
    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.aws.network.inventory import NetworkInventoryCollector
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class RegionalInventoryEvidenceSource(Protocol):
    """Regional EC2 and network inventory methods required by scanners."""

    def collect_cached_ec2_records(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Ec2InventoryCollector], list[Any]],
        period_key: str | None = None,
    ) -> list[Any]:
        """Return cached EC2 records collected for a named scanner evidence set."""
        ...

    def collect_cached_ec2_items_by_region(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [Ec2InventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> dict[str, list[dict[str, Any]]]:
        """Return cached EC2 inventory grouped by AWS region."""
        ...

    def get_cached_ec2_regions(
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        """Return cached regions where EC2 inventory collection is available."""
        ...

    def create_ec2_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector:
        """Create an audited EC2 inventory collector for scanner evidence reads."""
        ...

    def collect_cached_network_items_by_region(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [NetworkInventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> dict[str, list[dict[str, Any]]]:
        """Return cached network inventory grouped by AWS region."""
        ...

    def collect_cached_network_batch(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [NetworkInventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> NetworkInventoryBatch:
        """Return cached network inventory grouped by AWS region."""
        ...

    def collect_cached_network_nat_gateway_records(
        self,
        definition: ScannerDefinition,
    ) -> list[NatGatewayRecord]:
        """Return cached NAT gateway records for network-cost scanners."""
        ...

    def get_cached_network_regions(
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        """Return cached regions where network inventory collection is available."""
        ...

    def create_network_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector:
        """Create an audited network inventory collector for scanner evidence reads."""
        ...
