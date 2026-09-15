from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.platform.managed.helpers import (
    add_managed_platform_cost_context,
    build_managed_platform_collector,
    record_managed_platform_execution_detail,
)
from unio_collector.scanners.platform.opensearch.evidence import (
    OpenSearchCostReviewEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class OpenSearchCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> OpenSearchCostReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        records = collector.collect_opensearch_records()
        records = add_managed_platform_cost_context(records, context)
        regions = collector.get_available_regions()
        record_managed_platform_execution_detail(
            context,
            records,
            regions=regions,
            service_label="OpenSearch",
            resource_label="domain",
            resource_count=sum(record.domain_count for record in records),
            detail_counts={
                "total_instance_count": sum(record.total_instance_count for record in records),
                "total_ebs_volume_gb": sum(record.total_ebs_volume_gb for record in records),
                "multi_az_domain_count": sum(record.multi_az_domain_count for record in records),
                "warm_storage_domain_count": sum(record.warm_storage_domain_count for record in records),
            },
        )
        return OpenSearchCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="OpenSearchCostReviewScanner",
            implementation_module="unio_collector.scanners.platform.opensearch.scanner",
        )
