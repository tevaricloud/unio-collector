from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

from unio_collector.scanners.scanner.gateway.protocols import (
    ScannerAnalysisGatewayRuntime,
    ScannerCloudWatchGatewayRuntime,
    ScannerCostGatewayRuntime,
    ScannerDataGatewayRuntime,
    ScannerEc2GatewayRuntime,
    ScannerFindingGatewayRuntime,
    ScannerLambdaGatewayRuntime,
    ScannerNetworkGatewayRuntime,
    ScannerOptionsGatewayRuntime,
    ScannerS3GatewayRuntime,
    ScannerSecurityGatewayRuntime,
    ScannerTaggingGatewayRuntime,
    ScannerWarningGatewayRuntime,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cloudwatch import (
        CloudWatchLogMetricCollectionOptions,
        CloudWatchLogsCollector,
    )
    from unio_collector.aws.cost_explorer import (
        CostExplorerCollector,
        CostExplorerResult,
        DailyCostRecord,
    )
    from unio_collector.aws.ec2 import Ec2InventoryCollector
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
    from unio_collector.aws.network.batch import NetworkInventoryBatch
    from unio_collector.aws.network.inventory import NetworkInventoryCollector
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
        ResourceGroupsTaggingCollector,
    )
    from unio_collector.aws.s3 import (
        S3BucketIndexResult,
        S3LifecycleCollectionOptions,
    )
    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerRuntimeProtocol(
    ScannerAnalysisGatewayRuntime,
    ScannerCloudWatchGatewayRuntime,
    ScannerCostGatewayRuntime,
    ScannerDataGatewayRuntime,
    ScannerEc2GatewayRuntime,
    ScannerFindingGatewayRuntime,
    ScannerLambdaGatewayRuntime,
    ScannerNetworkGatewayRuntime,
    ScannerOptionsGatewayRuntime,
    ScannerS3GatewayRuntime,
    ScannerSecurityGatewayRuntime,
    ScannerTaggingGatewayRuntime,
    ScannerWarningGatewayRuntime,
    Protocol,
):
    """Typed scanner-facing subset of the scan runner."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102

    @property
    def cancellation_token(self) -> ScannerCancellationToken: ...  # noqa: D102

    @property
    def findings(self) -> list[Finding]: ...  # noqa: D102

    @findings.setter
    def findings(self, value: list[Finding]) -> None: ...

    @property
    def service_deltas(self) -> list[ServiceSpendDelta]: ...  # noqa: D102

    @service_deltas.setter
    def service_deltas(self, value: list[ServiceSpendDelta]) -> None: ...

    @property
    def scanner_data(self) -> dict[str, Any]: ...  # noqa: D102

    @scanner_data.setter
    def scanner_data(self, value: dict[str, Any]) -> None: ...

    @property
    def previous_period(self) -> CostPeriod: ...  # noqa: D102

    @previous_period.setter
    def previous_period(self, value: CostPeriod) -> None: ...

    @property
    def current_period(self) -> CostPeriod: ...  # noqa: D102

    @current_period.setter
    def current_period(self, value: CostPeriod) -> None: ...

    def create_audit_context(  # noqa: D102
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext: ...

    def create_cost_explorer_collector(  # noqa: D102
        self,
        audit_context: AwsAuditContext,
    ) -> CostExplorerCollector: ...

    def collect_cached_service_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult: ...

    def collect_cached_daily_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]: ...

    def collect_cached_daily_costs_with_context(  # noqa: D102
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]: ...

    def collect_cached_ec2_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        collect_records: Callable[[Any], list[Any]],
        period_key: str | None = None,
    ) -> list[Any]: ...

    def get_cached_ec2_regions(self, definition: ScannerDefinition) -> list[str]: ...  # noqa: D102

    def create_ec2_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> Ec2InventoryCollector: ...

    def collect_cached_ec2_items_by_region(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> dict[str, list[dict[str, Any]]]: ...

    def collect_cached_network_items_by_region(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> dict[str, list[dict[str, Any]]]: ...

    def collect_cached_network_batch(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_name: str,
        label: str,
        collect_items: Callable[[Any], dict[str, list[dict[str, Any]]]],
    ) -> NetworkInventoryBatch: ...

    def get_cached_network_regions(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[str]: ...

    def collect_cached_network_nat_gateway_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[Any]: ...

    def create_network_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str] | None = None,
    ) -> NetworkInventoryCollector: ...

    def collect_cached_resource_groups_tagging_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollectionResult: ...

    def create_resource_groups_tagging_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        regions: list[str],
    ) -> ResourceGroupsTaggingCollector: ...

    def collect_cached_log_groups_without_retention(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[Any]: ...

    def collect_cached_log_group_activity(  # noqa: D102
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]: ...

    def collect_cached_s3_lifecycle_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object: ...

    def collect_cached_s3_multipart_records(  # noqa: D102
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
    ) -> object: ...

    def collect_cached_s3_bucket_index(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult: ...

    def collect_cached_lambda_function_inventory(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]: ...

    def create_cloudwatch_logs_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector: ...

    def add_scanner_warning(self, scanner_id: str, warning: str) -> None: ...  # noqa: D102

    def add_scanner_coverage_note(  # noqa: D102
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None: ...

    def record_scanner_evidence_payload(  # noqa: D102
        self,
        scanner_id: str,
        payload: dict[str, Any],
    ) -> None: ...

    def is_cancelled(self) -> bool: ...  # noqa: D102

    def raise_if_cancelled(self) -> None: ...  # noqa: D102

    def time_remaining_seconds(self) -> float | None: ...  # noqa: D102
