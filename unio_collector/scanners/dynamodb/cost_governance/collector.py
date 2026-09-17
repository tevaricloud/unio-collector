from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.dynamodb import (
    DynamoDbRegionRecord,
    normalize_dynamodb_table_detail_regional_mode,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.dynamodb.cost_governance.evidence import (
    DynamoDbCostGovernanceEvidence,
)
from unio_collector.scanners.dynamodb.helpers import (
    build_dynamodb_collector,
    enrich_dynamodb_records_with_cost_context,
    get_dynamodb_regional_cost_context,
    parse_decimal,
)
from unio_collector.scanners.dynamodb.table_detail_scope import DynamoDbTableDetailScope
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.aws.dynamodb import DynamoDbInventoryCollector
    from unio_collector.scanners.scanner.context import ScannerContext


class DynamoDbCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> DynamoDbCostGovernanceEvidence:  # noqa: D102
        collector = build_dynamodb_collector(context)
        attempted_regions = collector.get_available_regions()
        detail_scope = self.build_table_detail_scope(
            context,
            attempted_regions=attempted_regions,
        )
        if detail_scope.detail_regions != attempted_regions:
            collector = build_dynamodb_collector(
                context,
                table_detail_regions=detail_scope.detail_regions,
            )
        records = collector.collect_records(context.options.get_scan_period())
        table_count = sum(record.table_count for record in records)
        detailed_table_count = sum(record.table_count for record in records if record.table_detail_collected)
        if detailed_table_count > 0:
            context.warnings.add_coverage_note(
                {
                    "note_type": "execution_detail",
                    "scope_area": "dynamodb_table_metadata",
                    "summary": (
                        f"DynamoDB table detail collection used up to {collector.max_table_workers} bounded worker(s) for {detailed_table_count} table(s)."
                    ),
                    "config_key": (f"{context.definition.scanner_id}.max_table_workers"),
                    "configured_value": collector.max_table_workers,
                    "table_count": detailed_table_count,
                    "result_scope": "current_scan",
                    "impact": ("Collection remains read-only; worker count only affects how many table metadata lookups can be in flight."),
                },
            )
        self.record_table_detail_scope_note(context, detail_scope)
        self.record_detail_mode_notes(context, collector)
        if table_count > 0:
            records = self.add_cost_explorer_context(
                records,
                context,
                regional_costs=detail_scope.regional_costs,
            )
        return DynamoDbCostGovernanceEvidence(
            records=records,
            regions=collector.get_available_regions(),
        )

    def build_table_detail_scope(  # noqa: D102
        self,
        context: ScannerContext,
        *,
        attempted_regions: list[str],
    ) -> DynamoDbTableDetailScope:
        mode = normalize_dynamodb_table_detail_regional_mode(
            context.options.get(
                "table_detail_regional_mode",
                "full",
            ),
        )
        if mode == "full":
            return DynamoDbTableDetailScope(
                mode=mode,
                attempted_regions=attempted_regions,
                detail_regions=attempted_regions,
            )
        regional_costs = self.collect_regional_costs_for_scope(context)
        if regional_costs is None:
            return DynamoDbTableDetailScope(
                mode=mode,
                attempted_regions=attempted_regions,
                detail_regions=attempted_regions,
            )
        regional_context = get_dynamodb_regional_cost_context(regional_costs)
        active_regions = [
            region
            for region in attempted_regions
            if (regional_context.get(region) is not None and parse_decimal(regional_context[region].get("current_cost")) > Decimal(0))
        ]
        if not active_regions:
            return DynamoDbTableDetailScope(
                mode=mode,
                attempted_regions=attempted_regions,
                detail_regions=attempted_regions,
                regional_costs=regional_costs,
            )
        summary_regions = [region for region in attempted_regions if region not in active_regions]
        return DynamoDbTableDetailScope(
            mode=mode,
            attempted_regions=attempted_regions,
            detail_regions=active_regions,
            summary_regions=summary_regions,
            regional_costs=regional_costs,
        )

    def collect_regional_costs_for_scope(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> list[DailyCostRecord] | None:
        try:
            return context.costs.collect_daily_costs(
                group_keys=("SERVICE", "REGION"),
            )
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            context.warnings.add(
                (
                    "Cost Explorer regional context was unavailable before "
                    "DynamoDB table-detail scope selection; full DynamoDB "
                    f"table-detail collection continued ({code})."
                ),
            )
            return None

    def record_table_detail_scope_note(  # noqa: D102
        self,
        context: ScannerContext,
        detail_scope: DynamoDbTableDetailScope,
    ) -> None:
        if not detail_scope.summary_regions:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "dynamodb_table_metadata",
                "summary": (
                    "DynamoDB table-detail collection used billing-active "
                    "mode; table names were listed in every selected region, "
                    "but DescribeTable, tag, metric, retention, and auto "
                    "scaling detail calls were skipped in regions without "
                    "visible regional DynamoDB spend."
                ),
                "configured_value": detail_scope.mode,
                "config_key": (f"{context.definition.scanner_id}.table_detail_regional_mode"),
                "result_scope": "current_scan",
                "attempted_region_count": len(detail_scope.attempted_regions),
                "detail_region_count": len(detail_scope.detail_regions),
                "summary_region_count": len(detail_scope.summary_regions),
                "detail_regions": detail_scope.detail_regions,
                "summary_regions": detail_scope.summary_regions,
                "impact": (
                    "Development scans still report table-name inventory in "
                    "summarized regions, but billing mode, table class, tag, "
                    "retention, metric, and auto scaling facts are not "
                    "confirmed there. Use full table_detail_regional_mode for "
                    "client-facing DynamoDB coverage."
                ),
            },
        )

    def record_detail_mode_notes(  # noqa: D102
        self,
        context: ScannerContext,
        collector: DynamoDbInventoryCollector,
    ) -> None:
        if collector.retention_detail_mode != "full":
            context.warnings.add_coverage_note(
                {
                    "note_type": "configuration_limit",
                    "scope_area": "dynamodb_retention_metadata",
                    "summary": ("DynamoDB point-in-time recovery and TTL detail calls were skipped by scanner configuration."),
                    "config_key": (f"{context.definition.scanner_id}.retention_detail_mode"),
                    "configured_value": collector.retention_detail_mode,
                    "result_scope": "current_scan",
                    "impact": (
                        "The scan still reviews table inventory, billing mode, "
                        "autoscaling, tags, and metrics, but does not confirm "
                        "per-table PITR or TTL state."
                    ),
                },
            )
        if collector.autoscaling_detail_mode != "full":
            context.warnings.add_coverage_note(
                {
                    "note_type": "configuration_limit",
                    "scope_area": "dynamodb_application_autoscaling_metadata",
                    "summary": ("DynamoDB Application Auto Scaling target and policy detail calls were skipped by scanner configuration."),
                    "config_key": (f"{context.definition.scanner_id}.autoscaling_detail_mode"),
                    "configured_value": collector.autoscaling_detail_mode,
                    "result_scope": "current_scan",
                    "impact": (
                        "The scan still reviews table inventory, billing mode, "
                        "tags, metrics, and Cost Explorer context, but does not "
                        "confirm per-table or per-index autoscaling target "
                        "coverage for this development run."
                    ),
                },
            )
        if collector.metric_detail_mode != "full":
            context.warnings.add_coverage_note(
                {
                    "note_type": "configuration_limit",
                    "scope_area": "dynamodb_cloudwatch_metrics",
                    "summary": ("DynamoDB table-level CloudWatch metric enrichment was skipped by scanner configuration."),
                    "config_key": (f"{context.definition.scanner_id}.metric_detail_mode"),
                    "configured_value": collector.metric_detail_mode,
                    "result_scope": "current_scan",
                    "impact": (
                        "The scan still reviews table inventory, billing mode, "
                        "autoscaling, tags, and Cost Explorer context, but does "
                        "not collect consumed-capacity, throttle, latency, or "
                        "system-error datapoints for this development run."
                    ),
                },
            )

    def add_cost_explorer_context(  # noqa: D102
        self,
        records: list[DynamoDbRegionRecord],
        context: ScannerContext,
        *,
        regional_costs: list[DailyCostRecord] | None = None,
    ) -> list[DynamoDbRegionRecord]:
        try:
            service_costs = context.costs.collect_service_costs()
            collected_regional_costs = context.costs.collect_daily_costs(group_keys=("SERVICE", "REGION")) if regional_costs is None else regional_costs
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            context.warnings.add(
                (f"DynamoDB Cost Explorer context was unavailable; metadata and CloudWatch metric findings continued ({code})."),
            )
            return records
        return enrich_dynamodb_records_with_cost_context(
            records,
            service_costs=service_costs,
            daily_costs=collected_regional_costs,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="DynamoDbCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.dynamodb.cost_governance.scanner",
        )
