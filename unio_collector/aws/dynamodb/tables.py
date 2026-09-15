# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    AwsCollectionTaskResult,
    record_collection_results,
)
from unio_collector.aws.dynamodb.region import DynamoDbRegionRecord
from unio_collector.aws.dynamodb.supplemental import (
    DynamoDbRegionSupplementalContext,
)
from unio_collector.aws.dynamodb.table import DynamoDbTableDetail
from unio_collector.aws.response_admission import (
    ProviderResponseError,
    iter_response_rows,
    require_response_mapping,
    require_response_string,
    require_response_strings,
)

if TYPE_CHECKING:
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


class DynamoDbTableMixin:  # noqa: D101
    def _build_table_summary_record(
        self,
        region: str,
        *,
        table_names: list[str],
        permission_errors: list[str],
    ) -> DynamoDbRegionRecord:
        return DynamoDbRegionRecord(
            account_id=self.account_id,
            region=region,
            table_detail_collected=False,
            table_count=len(table_names),
            sample_table_names=self._limit_samples(table_names),
            permission_errors=[
                *permission_errors,
                TABLE_DETAIL_SKIPPED_ERROR,
                METRIC_DETAIL_SKIPPED_ERROR,
                AUTOSCALING_DETAIL_SKIPPED_ERROR,
                *RETENTION_DETAIL_SKIPPED_ERRORS,
            ],
        )

    def _collect_region_supplemental_context(
        self,
        dynamodb: Any,  # noqa: ANN401
        autoscaling: Any | None,  # noqa: ANN401
        *,
        region: str,
        table_names: list[str],
        table_details: list[DynamoDbTableDetail],
        scan_period: ScanPeriod | None,
    ) -> DynamoDbRegionSupplementalContext:
        tags_by_table: dict[str, dict[str, str]] = {}
        scalable_targets: list[dict[str, Any]] = []
        scaling_policies: list[dict[str, Any]] = []
        metric_rollup = self._build_empty_metric_rollup()
        permission_errors: list[str] = []

        collectors = {
            "tags": lambda: self._collect_table_tags_context(
                dynamodb,
                region,
                table_details,
            ),
            "metrics": lambda: self._collect_metric_rollup_context(
                region,
                table_names,
                scan_period,
            ),
        }
        if autoscaling is not None:
            collectors["scalable_targets"] = lambda: self._collect_scalable_targets_context(autoscaling)
            collectors["scaling_policies"] = lambda: self._collect_scaling_policies_context(autoscaling)

        with ThreadPoolExecutor(
            max_workers=min(max(1, self.max_table_workers), len(collectors)),
            thread_name_prefix="unio-collector-dynamodb-context",
        ) as executor:
            future_map = {executor.submit(collector): name for name, collector in collectors.items()}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    value, errors = future.result()
                except Exception as exc:  # noqa: BLE001
                    code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
                    permission_errors.append(f"{name}:{code}")
                    continue
                self._extend_unique(permission_errors, errors)
                if name == "tags" and isinstance(value, dict):
                    tags_by_table = {table_name: dict(tags) for table_name, tags in value.items()}
                elif name == "metrics" and isinstance(value, dict):
                    metric_rollup = dict(value)
                elif name == "scalable_targets" and isinstance(value, list):
                    scalable_targets = list(value)
                elif name == "scaling_policies" and isinstance(value, list):
                    scaling_policies = list(value)

        return DynamoDbRegionSupplementalContext(
            tags_by_table=tags_by_table,
            scalable_targets=scalable_targets,
            scaling_policies=scaling_policies,
            metric_rollup=metric_rollup,
            permission_errors=permission_errors,
        )

    def _collect_table_tags_context(
        self,
        dynamodb: Any,  # noqa: ANN401
        region: str,
        table_details: list[DynamoDbTableDetail],
    ) -> tuple[dict[str, dict[str, str]], list[str]]:
        permission_errors: list[str] = []
        return (
            self._collect_table_tags(
                dynamodb,
                region,
                table_details,
                permission_errors,
            ),
            permission_errors,
        )

    def _collect_metric_rollup_context(
        self,
        region: str,
        table_names: list[str],
        scan_period: ScanPeriod | None,
    ) -> tuple[dict[str, Any], list[str]]:
        permission_errors: list[str] = []
        return (
            self._collect_metric_rollup(
                region,
                table_names,
                scan_period,
                permission_errors,
            ),
            permission_errors,
        )

    def _collect_scalable_targets_context(
        self,
        autoscaling: Any,  # noqa: ANN401
    ) -> tuple[list[dict[str, Any]], list[str]]:
        permission_errors: list[str] = []
        return (
            self._collect_scalable_targets(autoscaling, permission_errors),
            permission_errors,
        )

    def _collect_scaling_policies_context(
        self,
        autoscaling: Any,  # noqa: ANN401
    ) -> tuple[list[dict[str, Any]], list[str]]:
        permission_errors: list[str] = []
        return (
            self._collect_scaling_policies(autoscaling, permission_errors),
            permission_errors,
        )

    def _collect_table_names(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[str]:
        names: list[str] = []
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_tables",
                result_key="TableNames",
                request_cursor_key="ExclusiveStartTableName",
                response_cursor_keys=("LastEvaluatedTableName",),
            )
            for page in result.pages:
                names.extend(require_response_strings(page, "TableNames"))
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="list_tables",
                exc=exc,
            )
        return names

    def _describe_table(
        self,
        client: Any,  # noqa: ANN401
        table_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.describe_table(TableName=table_name)
            table = require_response_mapping(require_response_mapping(response).get("Table"))
            require_response_string(table.get("TableName"))
            require_response_string(table.get("TableStatus"))
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="describe_table",
                exc=exc,
            )
            return None
        return table

    def _collect_table_details(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        table_names: list[str],
        permission_errors: list[str],
    ) -> list[DynamoDbTableDetail]:
        tasks = [
            AwsCollectionTask(
                name=f"DynamoDbInventoryCollector:table-detail:{table_name}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region=region,
                service="dynamodb",
                operation=self._get_table_detail_operation_summary(),
                payload={"table_name": table_name},
                collect=lambda table_name=table_name: self._collect_table_detail(
                    client,
                    table_name,
                ),
            )
            for table_name in table_names
        ]
        results = AwsCollectionExecutor(
            max_workers=self.max_table_workers,
        ).run(tasks)
        record_collection_results(self.session, results)
        return self._build_table_details_from_results(
            results,
            permission_errors,
        )

    def _collect_table_detail(
        self,
        client: Any,  # noqa: ANN401
        table_name: str,
    ) -> DynamoDbTableDetail:
        permission_errors: list[str] = []
        table = self._describe_table(client, table_name, permission_errors)
        if self.retention_detail_mode == "summary":
            permission_errors.extend(RETENTION_DETAIL_SKIPPED_ERRORS)
            return DynamoDbTableDetail(
                table_name=table_name,
                table=table,
                permission_errors=permission_errors,
            )
        pitr_enabled = self._collect_table_pitr_enabled(
            client,
            table_name,
            permission_errors,
        )
        ttl_enabled = self._collect_table_ttl_enabled(
            client,
            table_name,
            permission_errors,
        )
        return DynamoDbTableDetail(
            table_name=table_name,
            table=table,
            pitr_enabled=pitr_enabled,
            ttl_enabled=ttl_enabled,
            permission_errors=permission_errors,
        )

    def _build_table_details_from_results(
        self,
        results: list[AwsCollectionTaskResult[DynamoDbTableDetail]],
        permission_errors: list[str],
    ) -> list[DynamoDbTableDetail]:
        details: list[DynamoDbTableDetail] = []
        for result in results:
            table_name = str(result.task.payload.get("table_name") or "")
            if result.status == "completed" and result.value is not None:
                details.append(result.value)
                self._extend_unique(permission_errors, result.value.permission_errors)
                continue
            errors = [f"table_detail:{result.error_code or 'UnavailableEvidence'}"]
            self._extend_unique(permission_errors, errors)
            details.append(DynamoDbTableDetail(table_name=table_name, permission_errors=errors))
        return details

    def _get_table_detail_operation_summary(self) -> str:
        if self.retention_detail_mode == "summary":
            return "DescribeTable"
        return "DescribeTable+DescribeContinuousBackups+DescribeTimeToLive"

    def _get_region_operation_summary(self) -> str:
        detail_operations = self._get_table_detail_operation_summary()
        metric_operation = "CloudWatchGetMetricData" if self.metric_detail_mode == "full" else "CloudWatchMetricsSkipped"
        autoscaling_operation = "DescribeScalableTargets+DescribeScalingPolicies" if self.autoscaling_detail_mode == "full" else "ApplicationAutoScalingSkipped"
        return f"ListTables+{detail_operations}+ResourceGroupsTaggingGetResources+ListTagsOfResourceFallback+{autoscaling_operation}+{metric_operation}"

    def _collect_table_tags(
        self,
        dynamodb_client: Any,  # noqa: ANN401
        region: str,
        table_details: list[DynamoDbTableDetail],
        permission_errors: list[str],
    ) -> dict[str, dict[str, str]]:
        tags = self._collect_table_tags_from_resource_groups_tagging(
            region,
            table_details,
            permission_errors,
        )
        if tags is not None:
            return tags
        return self._collect_table_tags_from_dynamodb(
            dynamodb_client,
            region,
            table_details,
            permission_errors,
        )

    def _collect_table_tags_from_resource_groups_tagging(
        self,
        region: str,
        table_details: list[DynamoDbTableDetail],
        permission_errors: list[str],
    ) -> dict[str, dict[str, str]] | None:
        table_arns = {
            str(detail.table.get("TableArn") or ""): detail.table_name for detail in table_details if detail.table is not None and detail.table.get("TableArn")
        }
        if not table_arns:
            return {}
        client = self._safe_client(
            "resourcegroupstaggingapi",
            region,
            permission_errors,
        )
        if client is None:
            return None
        try:
            result = self._pagination.collect_token_pages(
                client,
                "get_resources",
                result_key="ResourceTagMappingList",
                request_parameters={
                    "ResourcesPerPage": 100,
                    "ResourceTypeFilters": ["dynamodb:table"],
                },
                request_cursor_key="PaginationToken",
                response_cursor_keys=("PaginationToken",),
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="resourcegroupstaggingapi:get_resources",
                exc=exc,
            )
            return None
        tags_by_table: dict[str, dict[str, str]] = {}
        try:
            for mapping in iter_response_rows(result.pages, "ResourceTagMappingList"):
                table_name = table_arns.get(require_response_string(mapping.get("ResourceARN")))
                if not table_name:
                    continue
                tags_by_table[table_name] = self._convert_tag_list(
                    mapping.get("Tags"),
                )
        except ProviderResponseError as exc:
            self._record_collection_error(permission_errors, method_name="resourcegroupstaggingapi:get_resources", exc=exc)
        if set(table_arns.values()) - tags_by_table.keys():
            self._extend_unique(permission_errors, ["resourcegroupstaggingapi:get_resources:UnobservedTags"])
        return tags_by_table

    def _collect_table_tags_from_dynamodb(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        table_details: list[DynamoDbTableDetail],
        permission_errors: list[str],
    ) -> dict[str, dict[str, str]]:
        tasks = self._build_dynamodb_tag_tasks(client, region, table_details)
        results = AwsCollectionExecutor(
            max_workers=self.max_table_workers,
        ).run(tasks)
        record_collection_results(self.session, results)
        return self._build_table_tags_from_results(
            table_details,
            results,
            permission_errors,
        )
