from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.platform.managed.helpers import (
    add_managed_platform_cost_context,
    build_managed_platform_collector,
    record_managed_platform_execution_detail,
)
from unio_collector.scanners.platform.redshift.evidence import RedshiftCostReviewEvidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class RedshiftCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> RedshiftCostReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        records = collector.collect_redshift_records()
        records = add_managed_platform_cost_context(records, context)
        regions = collector.get_available_regions()
        record_managed_platform_execution_detail(
            context,
            records,
            regions=regions,
            service_label="Redshift",
            resource_label="cluster or serverless workgroup",
            resource_count=sum(record.cluster_count + record.serverless_workgroup_count for record in records),
            detail_counts={
                "cluster_count": sum(record.cluster_count for record in records),
                "serverless_workgroup_count": sum(record.serverless_workgroup_count for record in records),
                "total_node_count": sum(record.total_node_count for record in records),
                "paused_cluster_count": sum(record.paused_cluster_count for record in records),
                "serverless_base_capacity_rpu_total": sum(record.serverless_base_capacity_rpu_total for record in records),
            },
        )
        return RedshiftCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="RedshiftCostReviewScanner",
            implementation_module="unio_collector.scanners.platform.redshift.scanner",
        )
