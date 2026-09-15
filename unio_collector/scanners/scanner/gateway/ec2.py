from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerEc2GatewayRuntime


@dataclass(frozen=True)
class ScannerEc2Gateway:  # noqa: D101
    runtime: ScannerEc2GatewayRuntime
    definition: ScannerDefinition

    def collect_records(  # noqa: D102
        self,
        *,
        collection_name: str,
        collect_records: Callable[[Any], list[Any]],
        period_key: str | None = None,
    ) -> list[Any]:
        return self.runtime.collect_cached_ec2_records(
            self.definition,
            collection_name=collection_name,
            collect_records=collect_records,
            period_key=period_key,
        )

    def get_regions(self) -> list[str]:  # noqa: D102
        return self.runtime.get_cached_ec2_regions(self.definition)

    def create_collector(self, *, regions: list[str] | None = None) -> Any:  # noqa: ANN401, D102
        return self.runtime.create_ec2_collector(self.definition, regions=regions)

    def collect_items_by_region(  # noqa: D102
        self,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> dict[str, list[dict[str, Any]]]:
        return self.runtime.collect_cached_ec2_items_by_region(
            self.definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )
