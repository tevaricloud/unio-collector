from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.resource_groups.tagging import (
    DEFAULT_RESOURCE_TYPE_FILTERS,
    ResourceGroupsTaggingCollectionResult,
    ResourceGroupsTaggingCollector,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase
from unio_collector.scan_workflow.evidence.tagging_keys import (
    ResourceTaggingEvidenceCacheKeyBuilder,
    ResourceTaggingEvidenceLabelBuilder,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ResourceTaggingEvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def build_resource_tagging_cache_keys(  # noqa: D102
        self,
    ) -> ResourceTaggingEvidenceCacheKeyBuilder:
        return ResourceTaggingEvidenceCacheKeyBuilder(
            account_id=self.runner.runtime_state.account_id,
        )

    def build_resource_tagging_labels(self) -> ResourceTaggingEvidenceLabelBuilder:  # noqa: D102
        return ResourceTaggingEvidenceLabelBuilder()

    def collect_cached_resource_groups_tagging_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="resource_groups_tagging_api",
            label=(self.build_resource_tagging_labels().build_taggable_resources_label()),
        )
        collector = self.create_resource_groups_tagging_collector(
            definition,
            regions=regions,
        )
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "resource_groups_tagging_api",
            self.build_resource_tagging_cache_keys().build_taggable_resources_key(
                regions=regions,
                resource_type_filters=DEFAULT_RESOURCE_TYPE_FILTERS,
            ),
            collector.collect_taggable_resources,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="resource_groups_tagging_api",
            label=(self.build_resource_tagging_labels().build_taggable_resources_label()),
            access_status=access.status,
        )
        return access.value

    def create_resource_groups_tagging_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector:
        runtime_state = self.runner.runtime_state
        return ResourceGroupsTaggingCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=self.runner.create_audit_context(
                definition,
                "ResourceGroupsTaggingCollector",
            ),
            selected_regions=regions,
        )
