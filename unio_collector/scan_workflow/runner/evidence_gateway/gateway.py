from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.runner.evidence_gateway.cloudwatch import (
    CloudWatchEvidenceGateway,
)
from unio_collector.scan_workflow.runner.evidence_gateway.cost import CostEvidenceGateway
from unio_collector.scan_workflow.runner.evidence_gateway.lambda_inventory import (
    LambdaInventoryEvidenceGateway,
)
from unio_collector.scan_workflow.runner.evidence_gateway.notes import (
    EvidenceNoteGateway,
)
from unio_collector.scan_workflow.runner.evidence_gateway.prefetch import (
    SharedEvidencePrefetchGateway,
)
from unio_collector.scan_workflow.runner.evidence_gateway.regional import (
    RegionalInventoryEvidenceGateway,
)
from unio_collector.scan_workflow.runner.evidence_gateway.s3 import S3EvidenceGateway
from unio_collector.scan_workflow.runner.evidence_gateway.tagging import (
    ResourceTaggingEvidenceGateway,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cloudwatch import (
        CloudWatchLogMetricCollectionOptions,
        CloudWatchLogsCollector,
    )
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.aws.ec2 import Ec2InventoryCollector
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.aws.network.inventory import NetworkInventoryCollector
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
        ResourceGroupsTaggingCollector,
    )
    from unio_collector.aws.s3 import S3BucketIndexResult, S3LifecycleCollectionOptions
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        ScannerEvidenceCollectionGatewaySource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerRunnerEvidenceGateway:
    """Compose focused scanner evidence capabilities for runner compatibility."""

    def __init__(  # noqa: D107
        self,
        collection_service: ScannerEvidenceCollectionGatewaySource,
    ) -> None:
        self.prefetch = SharedEvidencePrefetchGateway(collection_service)
        self.cost = CostEvidenceGateway(collection_service)
        self.regional_inventory = RegionalInventoryEvidenceGateway(collection_service)
        self.tagging = ResourceTaggingEvidenceGateway(collection_service)
        self.cloudwatch = CloudWatchEvidenceGateway(collection_service)
        self.s3 = S3EvidenceGateway(collection_service)
        self.lambda_inventory = LambdaInventoryEvidenceGateway(collection_service)
        self.notes = EvidenceNoteGateway(collection_service)

    def prefetch_shared_evidence(
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        """Prefetch shared evidence needed by the selected scanner set."""
        self.prefetch.prefetch_shared_evidence(scanner_ids)

    def collect_cached_service_costs(
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult:
        """Return cached service-level Cost Explorer evidence for a scanner."""
        return self.cost.collect_cached_service_costs(definition)

    def collect_cached_daily_costs(
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily Cost Explorer evidence grouped by requested keys."""
        return self.cost.collect_cached_daily_costs(
            definition,
            group_keys=group_keys,
        )

    def collect_cached_daily_costs_with_context(
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily costs for an explicit scanner audit context."""
        return self.cost.collect_cached_daily_costs_with_context(
            audit_context,
            group_keys=group_keys,
        )

    def collect_cached_ec2_records(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Ec2InventoryCollector], list[Any]],
        period_key: str | None = None,
    ) -> list[Any]:
        """Return cached EC2 records collected for a named scanner evidence set."""
        return self.regional_inventory.collect_cached_ec2_records(
            definition,
            collection_name=collection_name,
            collect_records=collect_records,
            period_key=period_key,
        )

    def collect_cached_ec2_items_by_region(
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
        """Return cached EC2 inventory grouped by AWS region."""
        return self.regional_inventory.collect_cached_ec2_items_by_region(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def get_cached_ec2_regions(
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        """Return cached regions where EC2 inventory collection is available."""
        return self.regional_inventory.get_cached_ec2_regions(definition)

    def create_ec2_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector:
        """Create an audited EC2 inventory collector for scanner evidence reads."""
        return self.regional_inventory.create_ec2_collector(
            definition,
            regions=regions,
        )

    def collect_cached_network_items_by_region(
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
        """Return cached network inventory grouped by AWS region."""
        return self.regional_inventory.collect_cached_network_items_by_region(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def collect_cached_network_batch(
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
        """Return cached network inventory grouped by AWS region."""
        return self.regional_inventory.collect_cached_network_batch(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def collect_cached_network_nat_gateway_records(
        self,
        definition: ScannerDefinition,
    ) -> list[NatGatewayRecord]:
        """Return cached NAT gateway records for network-cost scanners."""
        return self.regional_inventory.collect_cached_network_nat_gateway_records(
            definition,
        )

    def get_cached_network_regions(
        self,
        definition: ScannerDefinition,
    ) -> list[str]:
        """Return cached regions where network inventory collection is available."""
        return self.regional_inventory.get_cached_network_regions(definition)

    def create_network_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector:
        """Create an audited network inventory collector for scanner evidence reads."""
        return self.regional_inventory.create_network_collector(
            definition,
            regions=regions,
        )

    def collect_cached_resource_groups_tagging_records(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult:
        """Return cached Resource Groups Tagging API evidence for regions."""
        return self.tagging.collect_cached_resource_groups_tagging_records(
            definition,
            regions=regions,
        )

    def create_resource_groups_tagging_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector:
        """Create an audited Resource Groups Tagging collector."""
        return self.tagging.create_resource_groups_tagging_collector(
            definition,
            regions=regions,
        )

    def collect_cached_log_groups_without_retention(
        self,
        definition: ScannerDefinition,
    ) -> list[object]:
        """Return cached CloudWatch log groups without retention policies."""
        return self.cloudwatch.collect_cached_log_groups_without_retention(
            definition,
        )

    def collect_cached_log_group_activity(
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[object]:
        """Return cached CloudWatch log group activity evidence."""
        return self.cloudwatch.collect_cached_log_group_activity(
            definition,
            metric_options=metric_options,
        )

    def create_cloudwatch_logs_collector(
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector:
        """Create an audited CloudWatch Logs collector for scanner evidence reads."""
        return self.cloudwatch.create_cloudwatch_logs_collector(definition)

    def collect_cached_s3_lifecycle_records(
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object:
        """Return cached S3 lifecycle inventory evidence for a scanner."""
        return self.s3.collect_cached_s3_lifecycle_records(
            definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            collection_options=collection_options,
        )

    def collect_cached_s3_multipart_records(
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        max_multipart_uploads_per_bucket: int,
        skip_buckets_with_abort_incomplete_rule: bool,
        max_multipart_buckets: int = 0,
        multipart_bucket_selection_mode: str = "inventory-order",
        lifecycle_collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object:
        """Return cached S3 multipart-upload evidence with lifecycle context."""
        return self.s3.collect_cached_s3_multipart_records(
            definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
            max_multipart_buckets=max_multipart_buckets,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
            lifecycle_collection_options=lifecycle_collection_options,
        )

    def collect_cached_s3_bucket_index(
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult:
        """Return cached S3 bucket index evidence for scanner reuse."""
        return self.s3.collect_cached_s3_bucket_index(
            definition,
            max_bucket_workers=max_bucket_workers,
        )

    def collect_cached_lambda_function_inventory(
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        """Return cached Lambda function inventory grouped by region."""
        return self.lambda_inventory.collect_cached_lambda_function_inventory(
            definition,
        )

    def add_cached_evidence_note(
        self,
        definition: ScannerDefinition,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner definition."""
        self.notes.add_cached_evidence_note(
            definition,
            namespace=namespace,
            label=label,
            access_status=access_status,
        )

    def add_cached_evidence_note_for_scanner(
        self,
        scanner_id: str,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner identifier."""
        self.notes.add_cached_evidence_note_for_scanner(
            scanner_id,
            namespace=namespace,
            label=label,
            access_status=access_status,
        )
