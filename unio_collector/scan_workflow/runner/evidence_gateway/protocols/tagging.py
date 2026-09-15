from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
        ResourceGroupsTaggingCollector,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ResourceTaggingEvidenceSource(Protocol):
    """Resource Groups Tagging evidence methods required by scanners."""

    def collect_cached_resource_groups_tagging_records(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult:
        """Return cached Resource Groups Tagging API evidence for regions."""
        ...

    def create_resource_groups_tagging_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector:
        """Create an audited Resource Groups Tagging collector."""
        ...
