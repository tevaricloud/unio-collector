from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerTaggingGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner tagging gateways."""

    def collect_cached_resource_groups_tagging_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult: ...
