from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.aws.ec2 import Ec2InventoryCollector
from unio_collector.scan_workflow.evidence.ec2.keys import (
    Ec2EvidenceCacheKeyBuilder,
    Ec2EvidenceLabelBuilder,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scanners.scanner.definition import ScannerDefinition


class Ec2EvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def build_ec2_cache_keys(self) -> Ec2EvidenceCacheKeyBuilder:  # noqa: D102
        return Ec2EvidenceCacheKeyBuilder(
            account_id=self.runner.runtime_state.account_id,
        )

    def build_ec2_labels(self) -> Ec2EvidenceLabelBuilder:  # noqa: D102
        return Ec2EvidenceLabelBuilder()

    def collect_cached_ec2_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Ec2InventoryCollector], list[Any]],
        period_key: str | None = None,
    ) -> list[Any]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="ec2_inventory",
            label=self.build_ec2_labels().build_records_label(
                collection_name=collection_name,
            ),
        )
        regions = self.get_cached_ec2_regions(definition)
        collector = self.create_ec2_collector(definition, regions=regions)
        key_parts = self.build_ec2_cache_keys().build_records_key(
            collection_name=collection_name,
            regions=regions,
            period_key=period_key,
        )
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "ec2_inventory",
            key_parts,
            lambda: collect_records(collector),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="ec2_inventory",
            label=self.build_ec2_labels().build_records_label(
                collection_name=collection_name,
            ),
            access_status=access.status,
        )
        return list(access.value)

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
    ) -> dict[str, list[dict[str, Any]]]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="ec2_inventory",
            label=label,
        )
        regions = self.get_cached_ec2_regions(definition)
        collector = self.create_ec2_collector(definition, regions=regions)
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "ec2_inventory",
            self.build_ec2_cache_keys().build_items_by_region_key(
                collection_name=collection_name,
                regions=regions,
            ),
            lambda: collect_items(collector),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="ec2_inventory",
            label=label,
            access_status=access.status,
        )
        return {str(region): list(items) for region, items in access.value.items()}

    def get_cached_ec2_regions(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="available_regions",
            label=self.build_ec2_labels().build_available_regions_label(),
        )
        selected_regions = self.runner.runtime_state.get_selected_regions()
        if selected_regions is not None:
            return sorted(selected_regions)
        collector = self.create_ec2_collector(definition, regions=None)
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "available_regions",
            self.build_ec2_cache_keys().build_available_regions_key(),
            collector.get_available_regions,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="available_regions",
            label=self.build_ec2_labels().build_available_regions_label(),
            access_status=access.status,
        )
        return list(access.value)

    def create_ec2_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector:
        runtime_state = self.runner.runtime_state
        return Ec2InventoryCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=self.runner.create_audit_context(
                definition,
                "Ec2InventoryCollector",
            ),
            selected_regions=regions,
        )
