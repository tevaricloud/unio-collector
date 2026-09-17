from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.platform.elasticache.evidence import (
    ElastiCacheCostReviewEvidence,
)
from unio_collector.scanners.platform.managed.helpers import (
    add_managed_platform_cost_context,
    build_managed_platform_collector,
    record_managed_platform_execution_detail,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.platform_inventory import ManagedPlatformInventoryCollector
    from unio_collector.scanners.scanner.context import ScannerContext


class ElastiCacheCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> ElastiCacheCostReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        records = collector.collect_elasticache_records(
            context.options.get_scan_period(),
        )
        records = add_managed_platform_cost_context(records, context)
        regions = collector.get_available_regions()
        record_managed_platform_execution_detail(
            context,
            records,
            regions=regions,
            service_label="ElastiCache",
            resource_label="cache cluster",
            resource_count=sum(record.cache_cluster_count for record in records),
            detail_counts={
                "replication_group_count": sum(record.replication_group_count for record in records),
                "total_node_count": sum(record.total_node_count for record in records),
                "metric_observation_count": sum(record.metric_observation_count for record in records),
                "low_activity_cluster_count": sum(record.low_activity_cluster_count for record in records),
                "capacity_pressure_cluster_count": sum(record.high_memory_pressure_cluster_count + record.eviction_signal_cluster_count for record in records),
            },
        )
        self.record_metric_detail_note(context, collector)
        return ElastiCacheCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def record_metric_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        collector: ManagedPlatformInventoryCollector,
    ) -> None:
        if collector.elasticache_metric_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "elasticache_cloudwatch_metrics",
                "summary": (
                    "ElastiCache CloudWatch metric detail collection used summary mode; GetMetricData calls were skipped for faster development scans."
                ),
                "configured_value": collector.elasticache_metric_detail_mode,
                "config_key": "elasticache-cost-review.metric_detail_mode",
                "result_scope": "current_scan",
                "impact": (
                    "Cluster, replication-group, node-count, multi-AZ, "
                    "failover, cluster-mode, engine/version, and Cost Explorer "
                    "context still run, but CPU, memory, connection, eviction, "
                    "and cache hit/miss metric signals are not confirmed in "
                    "this mode."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ElastiCacheCostReviewScanner",
            implementation_module="unio_collector.scanners.platform.elasticache.scanner",
        )
