from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.ec2 import Ec2InventoryCollector
    from unio_collector.scanners.scanner.definition import ScannerDefinition

Ec2Record = TypeVar("Ec2Record")


class ScannerEc2GatewayRuntime(Protocol):
    """Runtime capabilities required by scanner EC2 gateways."""

    def collect_cached_ec2_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Ec2InventoryCollector], list[Ec2Record]],
        period_key: str | None = None,
    ) -> list[Ec2Record]: ...

    def get_cached_ec2_regions(self, definition: ScannerDefinition) -> list[str]: ...  # noqa: D102

    def create_ec2_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector: ...

    def collect_cached_ec2_items_by_region(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[
            [Ec2InventoryCollector],
            dict[str, list[dict[str, Any]]],
        ],
    ) -> dict[str, list[dict[str, Any]]]: ...
