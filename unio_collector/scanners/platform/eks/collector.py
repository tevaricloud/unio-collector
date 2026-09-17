from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.platform.eks.evidence import EksCostRiskReviewEvidence
from unio_collector.scanners.platform.managed.helpers import (
    add_managed_platform_cost_context,
    build_managed_platform_collector,
    record_managed_platform_execution_detail,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class EksCostRiskReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> EksCostRiskReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        records = collector.collect_eks_records()
        records = add_managed_platform_cost_context(records, context)
        regions = collector.get_available_regions()
        record_managed_platform_execution_detail(
            context,
            records,
            regions=regions,
            service_label="EKS",
            resource_label="cluster",
            resource_count=sum(record.cluster_count for record in records),
            detail_counts={
                "nodegroup_count": sum(record.nodegroup_count for record in records),
                "fargate_profile_count": sum(record.fargate_profile_count for record in records),
                "public_endpoint_cluster_count": sum(record.public_endpoint_cluster_count for record in records),
                "untagged_cluster_count": sum(record.untagged_cluster_count for record in records),
            },
        )
        return EksCostRiskReviewEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="EksCostRiskReviewScanner",
            implementation_module="unio_collector.scanners.platform.eks.scanner",
        )
