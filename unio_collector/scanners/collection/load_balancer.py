from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.load_balancer import (
    LoadBalancerCollectionOptions,
    LoadBalancerInventoryCollector,
)

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class LoadBalancerIdleReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for load-balancer-idle-review."""

    collector_id = "LoadBalancerInventoryCollector"

    collector_type = LoadBalancerInventoryCollector

    def create_collector(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> LoadBalancerInventoryCollector:
        return context.security.create_regional_inventory_collector(
            LoadBalancerInventoryCollector,
            collector_name=self.collector_id,
            collection_options=self.build_collection_options(context),
        )

    def collect_inventory_records(  # noqa: D102
        self,
        collector: LoadBalancerInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        options = collector.collection_options
        self.record_target_health_detail_mode_note(context, options)
        self.record_tag_collection_note(context, options)
        return list(
            collector.collect_load_balancers(
                context.options.get_scan_period(),
            ),
        )

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: LoadBalancerInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, object]:
        del context
        return {
            "target_health_detail_mode": (collector.collection_options.target_health_detail_mode),
            "collect_tags": collector.collection_options.collect_tags,
        }

    def build_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> LoadBalancerCollectionOptions:
        return LoadBalancerCollectionOptions.create(
            target_health_detail_mode=context.options.get(
                "target_health_detail_mode",
                "full",
            ),
            collect_tags=context.options.get(
                "collect_tags",
                True,
            ),
        )

    def record_target_health_detail_mode_note(  # noqa: D102
        self,
        context: ScannerContext,
        options: LoadBalancerCollectionOptions,
    ) -> None:
        if options.target_health_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "load_balancer_target_health",
                "summary": ("Load balancer target health collection used summary mode; DescribeTargetHealth calls were skipped for faster development scans."),
                "configured_value": options.target_health_detail_mode,
                "config_key": ("load-balancer-idle-review.target_health_detail_mode"),
                "result_scope": "current_scan",
                "impact": (
                    "Summary mode preserves load balancer inventory, target "
                    "group count, and traffic metrics, but cannot classify a "
                    "load balancer as idle solely from missing healthy target "
                    "counts."
                ),
            },
        )

    def record_tag_collection_note(  # noqa: D102
        self,
        context: ScannerContext,
        options: LoadBalancerCollectionOptions,
    ) -> None:
        if options.collect_tags:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "load_balancer_tags",
                "summary": ("Load balancer tag collection was skipped by scanner configuration."),
                "configured_value": options.collect_tags,
                "config_key": "load-balancer-idle-review.collect_tags",
                "result_scope": "current_scan",
                "impact": ("Findings may have less ownership context, but traffic and target group evidence is still collected."),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="LoadBalancerIdleReviewScanner",
            implementation_module="unio_collector.scanners.load_balancer",
        )
