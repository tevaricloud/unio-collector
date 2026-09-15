from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.scan_workflow.aws.collector_factory import ScannerAwsCollectorFactory
from unio_collector.scan_workflow.scanner.evidence_payload_recorder import (
    ScannerEvidencePayloadRecorder,
)
from unio_collector.scan_workflow.scanner.note_recorder import ScannerRunNoteRecorder
from unio_collector.scanners.scanner.reference_time import AnalysisReferenceTime

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cloudwatch import CloudWatchLogMetricCollectionOptions, CloudWatchLogsCollector
    from unio_collector.aws.cost_explorer import (
        CostExplorerCollector,
        CostExplorerResult,
        DailyCostRecord,
    )
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
    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.adapter_contract import (
        ScannerRuntimeAdapterTarget,
    )
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition

Ec2Record = TypeVar("Ec2Record")


class ScannerRuntimeAdapter:
    """Expose the scanner-facing runtime contract without handing over runner."""

    def __init__(
        self,
        runner: ScannerRuntimeAdapterTarget,
        *,
        analysis_reference_time: AnalysisReferenceTime | None = None,
    ) -> None:
        """Bind scanner access to runner state and one analysis instant."""
        self._runner = runner
        self._analysis_reference_time = analysis_reference_time or AnalysisReferenceTime(
            datetime.now(UTC),
            "scanner_started_at",
        )

    @property
    def analysis_reference_time(self) -> AnalysisReferenceTime:
        """Return the stable reference time for this scanner execution."""
        return self._analysis_reference_time

    @property
    def findings(self) -> list[Finding]:
        """Return mutable findings collected by the active runner."""
        return self._runner.output_state.findings

    @findings.setter
    def findings(self, value: list[Finding]) -> None:
        """Replace findings collected by the active runner."""
        self._runner.output_state.findings = value

    @property
    def service_deltas(self) -> list[ServiceSpendDelta]:
        """Return service delta records collected by the active runner."""
        return self._runner.output_state.service_deltas

    @service_deltas.setter
    def service_deltas(self, value: list[ServiceSpendDelta]) -> None:
        """Replace service delta records collected by the active runner."""
        self._runner.output_state.service_deltas = value

    @property
    def scanner_data(self) -> dict[str, Any]:
        """Return scanner data collected by the active runner."""
        return self._runner.output_state.scanner_data

    @scanner_data.setter
    def scanner_data(self, value: dict[str, Any]) -> None:
        """Replace scanner data collected by the active runner."""
        self._runner.output_state.scanner_data = value

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return read-only runtime state for legacy scanner handlers."""
        return self._runner.runtime_state

    @property
    def cancellation_token(self) -> ScannerCancellationToken:
        """Return cooperative scanner cancellation and deadline state."""
        return self._runner.cancellation_token

    @property
    def active_attempt(self) -> ScannerAttemptContext | None:
        """Return the active scanner attempt context."""
        return getattr(self._runner, "active_attempt", None)

    def is_cancelled(self) -> bool:
        """Return whether the active scanner has been cancelled."""
        if self.active_attempt is not None:
            return not self.active_attempt.has_commit_authority()
        return self.cancellation_token.is_cancelled()

    def raise_if_cancelled(self) -> None:
        """Raise when the active scanner deadline has expired."""
        if self.active_attempt is not None:
            self.active_attempt.require_commit_authority()
            return
        self.cancellation_token.raise_if_cancelled()

    def time_remaining_seconds(self) -> float | None:
        """Return remaining scanner deadline budget, if configured."""
        return self.cancellation_token.time_remaining_seconds()

    @property
    def previous_period(self) -> CostPeriod:
        """Return the previous comparison period."""
        return self._runner.context_state.previous_period

    @previous_period.setter
    def previous_period(self, value: CostPeriod) -> None:
        """Replace the previous comparison period."""
        self._runner.context_state.previous_period = value

    @property
    def current_period(self) -> CostPeriod:
        """Return the current scan period."""
        return self._runner.context_state.current_period

    @current_period.setter
    def current_period(self, value: CostPeriod) -> None:
        """Replace the current scan period."""
        self._runner.context_state.current_period = value

    def create_audit_context(
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext:
        """Create an audited collector context for a scanner."""
        return ScannerAwsCollectorFactory(
            self.runtime_state,
            attempt=self.active_attempt,
        ).create_audit_context(
            definition,
            collector,
        )

    def create_cost_explorer_collector(
        self,
        audit_context: AwsAuditContext,
    ) -> CostExplorerCollector:
        """Create a Cost Explorer collector for legacy scanner adapters."""
        return ScannerAwsCollectorFactory(
            self.runtime_state,
        ).create_cost_explorer_collector(audit_context)

    def collect_cached_service_costs(
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult:
        """Collect cached service-level Cost Explorer evidence."""
        return self._runner.evidence_gateway.collect_cached_service_costs(definition)

    def collect_cached_daily_costs(
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Collect cached daily Cost Explorer evidence."""
        return self._runner.evidence_gateway.collect_cached_daily_costs(
            definition,
            group_keys=group_keys,
        )

    def collect_cached_daily_costs_with_context(
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Collect cached daily costs using a prepared audit context."""
        return self._runner.evidence_gateway.collect_cached_daily_costs_with_context(
            audit_context,
            group_keys=group_keys,
        )

    def collect_cached_ec2_records(
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Ec2InventoryCollector], list[Ec2Record]],
        period_key: str | None = None,
    ) -> list[Ec2Record]:
        """Collect cached EC2 records."""
        return self._runner.evidence_gateway.collect_cached_ec2_records(
            definition,
            collection_name=collection_name,
            collect_records=collect_records,
            period_key=period_key,
        )

    def get_cached_ec2_regions(self, definition: ScannerDefinition) -> list[str]:
        """Return regions represented by cached EC2 evidence."""
        return self._runner.evidence_gateway.get_cached_ec2_regions(definition)

    def create_ec2_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector:
        """Create an EC2 collector."""
        return self._runner.evidence_gateway.create_ec2_collector(
            definition,
            regions=regions,
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
        """Collect cached EC2 evidence grouped by region."""
        return self._runner.evidence_gateway.collect_cached_ec2_items_by_region(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
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
        """Collect cached network evidence grouped by region."""
        return self._runner.evidence_gateway.collect_cached_network_items_by_region(
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
        """Collect cached network evidence grouped by region."""
        return self._runner.evidence_gateway.collect_cached_network_batch(
            definition,
            collection_name=collection_name,
            label=label,
            collect_items=collect_items,
        )

    def get_cached_network_regions(self, definition: ScannerDefinition) -> list[str]:
        """Return regions represented by cached network evidence."""
        return self._runner.evidence_gateway.get_cached_network_regions(definition)

    def collect_cached_network_nat_gateway_records(
        self,
        definition: ScannerDefinition,
    ) -> list[NatGatewayRecord]:
        """Collect cached NAT gateway evidence."""
        return self._runner.evidence_gateway.collect_cached_network_nat_gateway_records(
            definition,
        )

    def create_network_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector:
        """Create a network inventory collector."""
        return self._runner.evidence_gateway.create_network_collector(
            definition,
            regions=regions,
        )

    def collect_cached_resource_groups_tagging_records(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult:
        """Collect cached Resource Groups Tagging API evidence."""
        return self._runner.evidence_gateway.collect_cached_resource_groups_tagging_records(
            definition,
            regions=regions,
        )

    def create_resource_groups_tagging_collector(
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector:
        """Create a Resource Groups Tagging API collector."""
        return self._runner.evidence_gateway.create_resource_groups_tagging_collector(
            definition,
            regions=regions,
        )

    def collect_cached_log_groups_without_retention(
        self,
        definition: ScannerDefinition,
    ) -> list[Any]:
        """Collect cached CloudWatch log groups without retention."""
        return self._runner.evidence_gateway.collect_cached_log_groups_without_retention(
            definition,
        )

    def collect_cached_log_group_activity(
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]:
        """Collect cached CloudWatch log-group activity evidence."""
        return self._runner.evidence_gateway.collect_cached_log_group_activity(
            definition,
            metric_options=metric_options,
        )

    def create_cloudwatch_logs_collector(
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector:
        """Create a CloudWatch Logs collector."""
        return self._runner.evidence_gateway.create_cloudwatch_logs_collector(
            definition,
        )

    def collect_cached_s3_lifecycle_records(
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object:
        """Collect cached S3 lifecycle evidence."""
        return self._runner.evidence_gateway.collect_cached_s3_lifecycle_records(
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
        """Collect cached S3 multipart-upload evidence."""
        return self._runner.evidence_gateway.collect_cached_s3_multipart_records(
            definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
            skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
            max_multipart_buckets=max_multipart_buckets,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            lifecycle_collection_options=lifecycle_collection_options,
        )

    def collect_cached_s3_bucket_index(
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult:
        """Collect cached S3 bucket-index evidence."""
        return self._runner.evidence_gateway.collect_cached_s3_bucket_index(
            definition,
            max_bucket_workers=max_bucket_workers,
        )

    def collect_cached_lambda_function_inventory(
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        """Collect cached Lambda function inventory evidence."""
        return self._runner.evidence_gateway.collect_cached_lambda_function_inventory(
            definition,
        )

    def add_scanner_warning(self, scanner_id: str, warning: str) -> None:
        """Record a scanner warning."""
        ScannerRunNoteRecorder(self._runner).add_scanner_warning(
            scanner_id,
            warning,
        )

    def add_scanner_coverage_note(
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None:
        """Record a scanner coverage note."""
        ScannerRunNoteRecorder(self._runner).add_scanner_coverage_note(
            scanner_id,
            note,
        )

    def record_scanner_evidence_payload(
        self,
        scanner_id: str,
        payload: dict[str, Any],
    ) -> None:
        """Record serialized scanner evidence for evidence-bundle replay."""
        ScannerEvidencePayloadRecorder(
            self._runner,
        ).record_scanner_evidence_payload(scanner_id, payload)
