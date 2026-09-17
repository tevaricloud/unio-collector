from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.scan_workflow.evidence.network.keys import (
    NetworkEvidenceCacheKeyBuilder,
    NetworkEvidenceLabelBuilder,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class NetworkEvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def build_network_cache_keys(self) -> NetworkEvidenceCacheKeyBuilder:  # noqa: D102
        return NetworkEvidenceCacheKeyBuilder(
            account_id=self.runner.runtime_state.account_id,
        )

    def build_network_labels(self) -> NetworkEvidenceLabelBuilder:  # noqa: D102
        return NetworkEvidenceLabelBuilder()

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
    ) -> dict[str, list[dict[str, Any]]]:
        return self.collect_cached_network_batch(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        ).as_dictionary()

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
    ) -> NetworkInventoryBatch:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="network_inventory",
            label=label,
        )
        regions = self.get_cached_network_regions(definition)
        collector = self.create_network_collector(definition, regions=regions)
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "network_inventory",
            self.build_network_cache_keys().build_items_by_region_key(
                collection_name=collection_name,
                regions=regions,
            ),
            lambda: collector.collected_batch(collection_name, collect_items(collector)),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="network_inventory",
            label=label,
            access_status=access.status,
        )
        return access.value

    def collect_cached_network_nat_gateway_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[NatGatewayRecord]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="network_inventory",
            label=self.build_network_labels().build_nat_gateway_records_label(),
        )
        regions = self.get_cached_network_regions(definition)
        collector = self.create_network_collector(definition, regions=regions)
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "network_inventory",
            self.build_network_cache_keys().build_nat_gateway_records_key(
                regions=regions,
            ),
            lambda: collector.collect_inventory_batch("nat_gateways"),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="network_inventory",
            label=self.build_network_labels().build_nat_gateway_records_label(),
            access_status=access.status,
        )
        if any(item.state != "complete" or not item.enumeration_normal_termination for item in access.value.coverage):
            message = "NAT inventory limitation: incomplete network enumeration"
            raise ValueError(message)
        return collector.build_nat_gateway_records(
            nat_gateways_by_region=access.value.as_dictionary(),
        )

    def get_cached_network_regions(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="available_regions",
            label=self.build_network_labels().build_available_regions_label(),
        )
        selected_regions = self.runner.runtime_state.get_selected_regions()
        if selected_regions is not None:
            return sorted(selected_regions)
        collector = self.create_network_collector(definition, regions=None)
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "available_regions",
            self.build_network_cache_keys().build_available_regions_key(),
            collector.get_available_regions,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="available_regions",
            label=self.build_network_labels().build_available_regions_label(),
            access_status=access.status,
        )
        return list(access.value)

    def create_network_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector:
        runtime_state = self.runner.runtime_state
        return NetworkInventoryCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=self.runner.create_audit_context(
                definition,
                "NetworkInventoryCollector",
            ),
            selected_regions=regions,
        )
