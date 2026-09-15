from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.platform.api_gateway.evidence import (
    ApiGatewayCostReviewEvidence,
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


class ApiGatewayCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> ApiGatewayCostReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        records = collector.collect_api_gateway_records()
        records = add_managed_platform_cost_context(records, context)
        regions = collector.get_available_regions()
        record_managed_platform_execution_detail(
            context,
            records,
            regions=regions,
            service_label="API Gateway",
            resource_label="stage",
            resource_count=sum(record.stage_count for record in records),
            detail_counts={
                "rest_api_count": sum(record.rest_api_count for record in records),
                "http_api_count": sum(record.http_api_count for record in records),
                "websocket_api_count": sum(record.websocket_api_count for record in records),
                "vpc_link_count": sum(record.vpc_link_count for record in records),
                "cache_enabled_stage_count": sum(record.cache_enabled_stage_count for record in records),
                "observability_stage_setting_count": sum(
                    record.access_logging_stage_count
                    + record.execution_logging_stage_count
                    + record.detailed_metrics_stage_count
                    + record.data_trace_stage_count
                    + record.xray_tracing_stage_count
                    for record in records
                ),
            },
        )
        self.record_vpc_link_detail_note(context, collector)
        return ApiGatewayCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def record_vpc_link_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        collector: ManagedPlatformInventoryCollector,
    ) -> None:
        if collector.api_gateway_vpc_link_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "api_gateway_vpc_links",
                "summary": ("API Gateway VPC link detail collection used summary mode; GetVpcLinks calls were skipped for faster development scans."),
                "configured_value": collector.api_gateway_vpc_link_detail_mode,
                "config_key": "api-gateway-cost-review.vpc_link_detail_mode",
                "result_scope": "current_scan",
                "impact": (
                    "API, stage, route, cache, logging, tracing, CORS, and throttling checks still run, but VPC link findings cannot be confirmed in this mode."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ApiGatewayCostReviewScanner",
            implementation_module="unio_collector.scanners.platform.api_gateway.scanner",
        )
