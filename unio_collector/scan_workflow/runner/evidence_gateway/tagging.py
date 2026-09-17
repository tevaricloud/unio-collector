from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
        ResourceGroupsTaggingCollector,
    )
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        ResourceTaggingEvidenceSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ResourceTaggingEvidenceGateway:
    """Delegate Resource Groups Tagging collection to the tagging source."""

    def __init__(self, source: ResourceTaggingEvidenceSource) -> None:  # noqa: D107
        self._source = source

    def collect_cached_resource_groups_tagging_records(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult:
        """Return cached Resource Groups Tagging API evidence for regions."""
        return self._source.collect_cached_resource_groups_tagging_records(
            definition,
            regions=regions,
        )

    def create_resource_groups_tagging_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector:
        """Create an audited Resource Groups Tagging collector."""
        return self._source.create_resource_groups_tagging_collector(
            definition,
            regions=regions,
        )
