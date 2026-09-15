from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerTaggingGatewayRuntime


@dataclass(frozen=True)
class ScannerTaggingGateway:  # noqa: D101
    runtime: ScannerTaggingGatewayRuntime
    definition: ScannerDefinition

    def collect_resource_groups_records(self, *, regions: list[str]) -> Any:  # noqa: ANN401, D102
        return self.runtime.collect_cached_resource_groups_tagging_records(
            self.definition,
            regions=regions,
        )
