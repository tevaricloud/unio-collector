from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection import (
    RegionalAwsCollectionRunner,
)
from unio_collector.aws.dynamodb.classifier import DynamoDbTableClassifier
from unio_collector.aws.dynamodb.helpers import DynamoDbHelperMixin
from unio_collector.aws.dynamodb.metrics import DynamoDbMetricMixin
from unio_collector.aws.dynamodb.region import DynamoDbRegionRecord
from unio_collector.aws.dynamodb.supplemental import DynamoDbRegionSupplementalContext
from unio_collector.aws.dynamodb.table import DynamoDbTableDetail
from unio_collector.aws.dynamodb.tables import DynamoDbTableMixin
from unio_collector.aws.dynamodb.tag_result import DynamoDbTableTagResult
from unio_collector.aws.pagination import AwsPaginationHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.core.scan.period import ScanPeriod

DYNAMODB_RETENTION_DETAIL_MODES = {"full", "summary"}
DYNAMODB_METRIC_DETAIL_MODES = {"full", "summary"}
DYNAMODB_AUTOSCALING_DETAIL_MODES = {"full", "summary"}
DYNAMODB_TABLE_DETAIL_REGIONAL_MODES = {"full", "billing-active"}
TABLE_DETAIL_SKIPPED_ERROR = "table_detail:skipped_by_regional_collection_mode"
RETENTION_DETAIL_SKIPPED_ERRORS = (
    "describe_continuous_backups:skipped_by_retention_detail_mode",
    "describe_time_to_live:skipped_by_retention_detail_mode",
)
METRIC_DETAIL_SKIPPED_ERROR = "cloudwatch_metrics:skipped_by_metric_detail_mode"
AUTOSCALING_DETAIL_SKIPPED_ERROR = "application_autoscaling:skipped_by_autoscaling_detail_mode"


class DynamoDbInventoryCollector(
    DynamoDbTableMixin,
    DynamoDbMetricMixin,
    DynamoDbHelperMixin,
):
    """Collect read-only DynamoDB metadata for cost governance review."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        max_table_workers: int | None = None,
        retention_detail_mode: str = "full",
        metric_detail_mode: str = "full",
        autoscaling_detail_mode: str = "full",
        table_detail_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.max_table_workers = max(1, max_table_workers or self._get_max_workers())
        self.retention_detail_mode = normalize_dynamodb_retention_detail_mode(
            retention_detail_mode,
        )
        self.metric_detail_mode = normalize_dynamodb_metric_detail_mode(
            metric_detail_mode,
        )
        self.autoscaling_detail_mode = normalize_dynamodb_autoscaling_detail_mode(
            autoscaling_detail_mode,
        )
        self.table_detail_regions = {region for region in table_detail_regions if region} if table_detail_regions is not None else None
        self._pagination = AwsPaginationHelper()
        self._available_regions_cache: list[str] | None = None
        self._table_classifier = DynamoDbTableClassifier()

    def collect_records(  # noqa: D102
        self,
        scan_period: ScanPeriod | None = None,
    ) -> list[DynamoDbRegionRecord]:
        result = RegionalAwsCollectionRunner(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="DynamoDbInventoryCollector",
        ).collect_region_lists(
            regions=self.get_available_regions(),
            service="dynamodb",
            operation=self._get_region_operation_summary(),
            collect_region=lambda region: self._collect_region_record(
                region,
                scan_period,
            ),
        )
        return result.values

    def _collect_region_record(
        self,
        region: str,
        scan_period: ScanPeriod | None = None,
    ) -> list[DynamoDbRegionRecord]:
        permission_errors: list[str] = []
        dynamodb = self._safe_client("dynamodb", region, permission_errors)
        if dynamodb is None:
            return [
                DynamoDbRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]

        table_names = self._collect_table_names(dynamodb, permission_errors)
        if not self._should_collect_table_detail_for_region(region):
            return [
                self._build_table_summary_record(
                    region,
                    table_names=table_names,
                    permission_errors=permission_errors,
                ),
            ]
        table_details = self._collect_table_details(
            dynamodb,
            region,
            table_names,
            permission_errors,
        )
        tables = [detail.table for detail in table_details if detail.table is not None]
        pitr_enabled = {detail.table_name for detail in table_details if detail.pitr_enabled}
        ttl_enabled = {detail.table_name for detail in table_details if detail.ttl_enabled}
        autoscaling_errors: list[str] = []
        autoscaling = self._build_autoscaling_client_for_provisioned_tables(
            region,
            tables,
            autoscaling_errors,
        )
        self._extend_unique(permission_errors, autoscaling_errors)
        supplemental = self._collect_region_supplemental_context(
            dynamodb,
            autoscaling,
            region=region,
            table_names=table_names,
            table_details=table_details,
            scan_period=scan_period,
        )
        self._extend_unique(permission_errors, supplemental.permission_errors)
        tags_by_table = supplemental.tags_by_table
        scalable_targets = supplemental.scalable_targets
        scaling_policies = supplemental.scaling_policies
        metric_rollup = supplemental.metric_rollup
        pitr_disabled_tables = self._table_classifier.collect_tables_without_feature_status(
            table_details,
            enabled_table_names=pitr_enabled,
            error_method_name="describe_continuous_backups",
        )
        ttl_disabled_tables = self._table_classifier.collect_tables_without_feature_status(
            table_details,
            enabled_table_names=ttl_enabled,
            error_method_name="describe_time_to_live",
        )
        if any(
            error.startswith(("application_autoscaling:", "application-autoscaling:", "describe_scalable_targets:", "describe_scaling_policies:"))
            for error in permission_errors
        ):
            provisioned_tables_without_autoscaling: list[str] = []
            provisioned_gsis_without_autoscaling: list[str] = []
        else:
            provisioned_tables_without_autoscaling = self._table_classifier.collect_provisioned_tables_without_autoscaling(
                tables,
                scalable_targets,
            )
            provisioned_gsis_without_autoscaling = self._table_classifier.collect_provisioned_gsis_without_autoscaling(
                tables,
                scalable_targets,
            )
        untagged_tables = [table_name for table_name in table_names if table_name in tags_by_table and not tags_by_table[table_name]]

        return [
            DynamoDbRegionRecord(
                account_id=self.account_id,
                region=region,
                table_count=len(table_names),
                active_table_count=sum(1 for table in tables if self._table_classifier.is_active_table(table)),
                pay_per_request_table_count=sum(1 for table in tables if self._table_classifier.is_pay_per_request_table(table)),
                provisioned_table_count=sum(1 for table in tables if self._table_classifier.is_provisioned_table(table)),
                standard_ia_table_count=sum(1 for table in tables if self._table_classifier.is_standard_ia_table(table)),
                stream_enabled_table_count=sum(1 for table in tables if self._table_classifier.has_stream_enabled(table)),
                pitr_enabled_table_count=len(pitr_enabled),
                pitr_disabled_table_count=len(pitr_disabled_tables),
                ttl_enabled_table_count=len(ttl_enabled),
                ttl_disabled_table_count=len(ttl_disabled_tables),
                global_secondary_index_count=sum(len(self._table_classifier.get_global_secondary_indexes(table)) for table in tables),
                provisioned_global_secondary_index_count=sum(
                    self._table_classifier.count_provisioned_global_secondary_indexes(
                        table,
                    )
                    for table in tables
                ),
                provisioned_table_without_autoscaling_count=len(
                    provisioned_tables_without_autoscaling,
                ),
                provisioned_gsi_without_autoscaling_count=len(
                    provisioned_gsis_without_autoscaling,
                ),
                total_provisioned_read_capacity=sum(self._table_classifier.get_provisioned_read_capacity(table) for table in tables),
                total_provisioned_write_capacity=sum(self._table_classifier.get_provisioned_write_capacity(table) for table in tables),
                autoscaling_target_count=len(scalable_targets),
                autoscaling_policy_count=len(scaling_policies),
                tagged_table_count=sum(1 for tags in tags_by_table.values() if tags),
                untagged_table_count=sum(1 for tags in tags_by_table.values() if not tags),
                sample_table_names=self._limit_samples(table_names),
                sample_pay_per_request_tables=self._limit_samples(
                    [self._table_classifier.get_table_name(table) for table in tables if self._table_classifier.is_pay_per_request_table(table)],
                ),
                sample_provisioned_tables=self._limit_samples(
                    [self._table_classifier.get_table_name(table) for table in tables if self._table_classifier.is_provisioned_table(table)],
                ),
                sample_standard_ia_tables=self._limit_samples(
                    [self._table_classifier.get_table_name(table) for table in tables if self._table_classifier.is_standard_ia_table(table)],
                ),
                sample_stream_enabled_tables=self._limit_samples(
                    [self._table_classifier.get_table_name(table) for table in tables if self._table_classifier.has_stream_enabled(table)],
                ),
                sample_pitr_enabled_tables=self._limit_samples(sorted(pitr_enabled)),
                sample_pitr_disabled_tables=self._limit_samples(pitr_disabled_tables),
                sample_ttl_enabled_tables=self._limit_samples(sorted(ttl_enabled)),
                sample_ttl_disabled_tables=self._limit_samples(ttl_disabled_tables),
                sample_provisioned_tables_without_autoscaling=self._limit_samples(
                    provisioned_tables_without_autoscaling,
                ),
                sample_provisioned_gsis_without_autoscaling=self._limit_samples(
                    provisioned_gsis_without_autoscaling,
                ),
                sample_untagged_tables=self._limit_samples(untagged_tables),
                sample_tag_keys=self._limit_samples(
                    sorted(
                        {tag_key for tags in tags_by_table.values() for tag_key in tags},
                    ),
                ),
                metric_table_count=metric_rollup["metric_table_count"],
                metric_observation_count=metric_rollup["metric_observation_count"],
                consumed_capacity_table_count=(metric_rollup["consumed_capacity_table_count"]),
                throttle_signal_table_count=(metric_rollup["throttle_signal_table_count"]),
                system_error_signal_table_count=(metric_rollup["system_error_signal_table_count"]),
                average_daily_read_capacity_units=(metric_rollup["average_daily_read_capacity_units"]),
                average_daily_write_capacity_units=(metric_rollup["average_daily_write_capacity_units"]),
                sample_metric_table_names=metric_rollup["sample_metric_table_names"],
                observed_metric_names=metric_rollup["observed_metric_names"],
                permission_errors=permission_errors,
            ),
        ]

    def _should_collect_table_detail_for_region(self, region: str) -> bool:
        if self.table_detail_regions is None:
            return True
        return region in self.table_detail_regions


def normalize_dynamodb_retention_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in DYNAMODB_RETENTION_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(DYNAMODB_RETENTION_DETAIL_MODES))
    msg = f"DynamoDB retention_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_dynamodb_metric_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in DYNAMODB_METRIC_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(DYNAMODB_METRIC_DETAIL_MODES))
    msg = f"DynamoDB metric_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_dynamodb_autoscaling_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in DYNAMODB_AUTOSCALING_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(DYNAMODB_AUTOSCALING_DETAIL_MODES))
    msg = f"DynamoDB autoscaling_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_dynamodb_table_detail_regional_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in DYNAMODB_TABLE_DETAIL_REGIONAL_MODES:
        return normalized
    allowed = ", ".join(sorted(DYNAMODB_TABLE_DETAIL_REGIONAL_MODES))
    msg = f"DynamoDB table_detail_regional_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


__all__ = [
    "AUTOSCALING_DETAIL_SKIPPED_ERROR",
    "DYNAMODB_AUTOSCALING_DETAIL_MODES",
    "DYNAMODB_METRIC_DETAIL_MODES",
    "DYNAMODB_RETENTION_DETAIL_MODES",
    "DYNAMODB_TABLE_DETAIL_REGIONAL_MODES",
    "METRIC_DETAIL_SKIPPED_ERROR",
    "RETENTION_DETAIL_SKIPPED_ERRORS",
    "TABLE_DETAIL_SKIPPED_ERROR",
    "DynamoDbInventoryCollector",
    "DynamoDbRegionRecord",
    "DynamoDbRegionSupplementalContext",
    "DynamoDbTableClassifier",
    "DynamoDbTableDetail",
    "DynamoDbTableTagResult",
    "normalize_dynamodb_autoscaling_detail_mode",
    "normalize_dynamodb_metric_detail_mode",
    "normalize_dynamodb_retention_detail_mode",
    "normalize_dynamodb_table_detail_regional_mode",
]
