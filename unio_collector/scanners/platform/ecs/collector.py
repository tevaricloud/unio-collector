from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING

from unio_collector.aws import errors as aws_errors
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cost_context import get_regional_cost_context
from unio_collector.scanners.platform.ecs.evidence import (
    EcsCostGovernanceReviewEvidence,
)
from unio_collector.scanners.platform.ecs.regional_scope import (
    EcsRegionalCollectionScope,
)
from unio_collector.scanners.platform.managed.helpers import (
    add_managed_platform_cost_context,
    build_managed_platform_collector,
    collect_managed_platform_regional_costs,
    record_managed_platform_execution_detail,
)
from unio_collector.scanners.platform.managed.types import (
    PLATFORM_COST_EXPLORER_SERVICE_NAMES,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.aws.platform_inventory import ManagedPlatformInventoryCollector
    from unio_collector.scanners.scanner.context import ScannerContext


class EcsCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> EcsCostGovernanceReviewEvidence:  # noqa: D102
        collector = build_managed_platform_collector(context)
        attempted_regions = collector.get_available_regions()
        regional_costs = self.collect_regional_costs_for_scope(context)
        collection_scope = self.build_regional_collection_scope(
            context,
            collector,
            attempted_regions=attempted_regions,
            regional_costs=regional_costs or [],
        )
        if collection_scope.collection_regions != attempted_regions:
            collector = build_managed_platform_collector(
                context,
                selected_regions=collection_scope.collection_regions,
            )
        records = collector.collect_ecs_records()
        records = add_managed_platform_cost_context(
            records,
            context,
            regional_costs=regional_costs,
        )
        record_managed_platform_execution_detail(
            context,
            records,
            regions=attempted_regions,
            service_label="ECS",
            resource_label="service",
            resource_count=sum(record.service_count for record in records),
            detail_counts={
                "cluster_count": sum(record.cluster_count for record in records),
                "desired_task_count": sum(record.desired_task_count for record in records),
                "running_task_count": sum(record.running_task_count for record in records),
                "fargate_service_count": sum(record.fargate_service_count for record in records),
                "service_without_running_tasks_count": sum(record.service_without_running_tasks_count for record in records),
                "untagged_service_count": sum(record.untagged_service_count for record in records),
            },
        )
        self.record_task_definition_detail_note(context, collector)
        self.record_regional_collection_note(context, collection_scope)
        return EcsCostGovernanceReviewEvidence(
            records=records,
            regions=attempted_regions,
        )

    def record_task_definition_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        collector: ManagedPlatformInventoryCollector,
    ) -> None:
        if collector.ecs_task_definition_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "ecs_task_definitions",
                "summary": ("ECS task definition detail collection used summary mode; DescribeTaskDefinition calls were skipped for faster development scans."),
                "configured_value": collector.ecs_task_definition_detail_mode,
                "config_key": ("ecs-cost-governance-review.task_definition_detail_mode"),
                "result_scope": "current_scan",
                "impact": (
                    "Cluster, service, task-count, launch-type, deployment, "
                    "event, and tag checks still run, but task definition CPU "
                    "and memory sizing facts are not confirmed in this mode."
                ),
            },
        )

    def collect_regional_costs_for_scope(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> list[DailyCostRecord] | None:
        try:
            return collect_managed_platform_regional_costs(context)
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            context.warnings.add(
                (
                    "Cost Explorer regional context was unavailable before ECS "
                    "regional collection scope selection; full ECS regional "
                    f"collection continued ({code})."
                ),
            )
            return None

    def build_regional_collection_scope(  # noqa: D102
        self,
        context: ScannerContext,
        collector: ManagedPlatformInventoryCollector,
        *,
        attempted_regions: list[str],
        regional_costs: list[DailyCostRecord],
    ) -> EcsRegionalCollectionScope:
        mode = collector.ecs_regional_collection_mode
        if mode == "full":
            return EcsRegionalCollectionScope(
                mode=mode,
                attempted_regions=attempted_regions,
                collection_regions=attempted_regions,
            )
        regional_context = get_regional_cost_context(
            regional_costs,
            service_names=PLATFORM_COST_EXPLORER_SERVICE_NAMES[context.definition.scanner_id],
        )
        active_regions = [
            region for region in attempted_regions if (regional_context.get(region) is not None and regional_context[region].current_cost > Decimal(0))
        ]
        if not active_regions:
            return EcsRegionalCollectionScope(
                mode=mode,
                attempted_regions=attempted_regions,
                collection_regions=attempted_regions,
            )
        skipped_regions = [region for region in attempted_regions if region not in active_regions]
        return EcsRegionalCollectionScope(
            mode=mode,
            attempted_regions=attempted_regions,
            collection_regions=active_regions,
            skipped_regions=skipped_regions,
        )

    def record_regional_collection_note(  # noqa: D102
        self,
        context: ScannerContext,
        collection_scope: EcsRegionalCollectionScope,
    ) -> None:
        if not collection_scope.skipped_regions:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "ecs_regional_collection",
                "summary": (
                    "ECS regional collection used billing-active mode; ECS "
                    "metadata calls were skipped in selected regions without "
                    "visible ECS or Fargate Cost Explorer spend."
                ),
                "configured_value": collection_scope.mode,
                "config_key": "ecs-cost-governance-review.regional_collection_mode",
                "result_scope": "current_scan",
                "attempted_region_count": len(collection_scope.attempted_regions),
                "collection_region_count": len(collection_scope.collection_regions),
                "skipped_region_count": len(collection_scope.skipped_regions),
                "collection_regions": collection_scope.collection_regions,
                "skipped_regions": collection_scope.skipped_regions,
                "impact": (
                    "Development scans keep ECS metadata collection in regions "
                    "with visible ECS or Fargate spend. EC2-backed ECS services "
                    "in skipped regions may be missed when their supporting "
                    "cost is recorded under EC2 rather than ECS or Fargate."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="EcsCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.platform.ecs.scanner",
        )
