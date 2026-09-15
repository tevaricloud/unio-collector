from __future__ import annotations  # noqa: D100

import threading
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.collection import (
    RegionalAwsCollectionRunner,
)
from unio_collector.aws.errors import get_aws_error_code
from unio_collector.aws.lambda_cost.cycle.collection_summary import (
    LambdaCostCycleCollectionSummary,
)
from unio_collector.aws.lambda_cost.cycle.inventory.metrics import (
    LambdaMetricCollectionMixin,
)
from unio_collector.aws.lambda_cost.cycle.inventory.s3 import LambdaS3SignalCollectionMixin
from unio_collector.aws.lambda_cost.cycle.record import LambdaCostCycleRecord
from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
from unio_collector.aws.lambda_cost.function.tag_evidence import LambdaTagEvidence
from unio_collector.aws.lambda_cost.policy_result import (
    LambdaPolicyTargetCollectionResult,
)
from unio_collector.aws.lambda_cost.s3.selector import (
    LambdaS3NotificationBucketSelector,
)
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.response_admission import iter_response_rows, require_response_mapping, require_response_string
from unio_collector.aws.s3.notification.summary import S3NotificationScanSummary
from unio_collector.aws.serverless.inventory_helpers import (
    function_name_from_arn,
    group_s3_notifications_by_function,
    normalize_s3_notification_detail_mode,
    object_mapping,
    optional_int_value,
    optional_str,
    string_list,
    string_mapping,
)

if TYPE_CHECKING:
    from unio_collector.aws.audit import AuditedAwsClient, AwsAuditContext
    from unio_collector.aws.lambda_cost.function.policy import LambdaFunctionPolicyTarget
    from unio_collector.aws.s3 import S3BucketIndexResult
    from unio_collector.aws.s3.lambda_notification import S3LambdaNotificationRecord
    from unio_collector.core.scan.period import ScanPeriod


class LambdaCostCycleInventoryCollector(  # noqa: D101
    LambdaS3SignalCollectionMixin,
    LambdaMetricCollectionMixin,
):
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        max_s3_buckets: int | None = 25,
        s3_notification_worker_count: int = 8,
        s3_policy_scan_max_functions: int = 50,
        collect_tags: bool = True,
        s3_notification_detail_mode: str = "full",
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.max_s3_buckets = max_s3_buckets
        self.s3_notification_worker_count = s3_notification_worker_count
        self.s3_policy_scan_max_functions = s3_policy_scan_max_functions
        self.collect_tags = collect_tags
        self.s3_notification_detail_mode = normalize_s3_notification_detail_mode(
            s3_notification_detail_mode,
        )
        self._pagination = AwsPaginationHelper()
        self._function_inventory_by_region: dict[
            str,
            list[LambdaFunctionInventoryRecord],
        ] = {}
        self._function_inventory_lock = threading.Lock()
        self.s3_notification_scan_summary = S3NotificationScanSummary(
            max_s3_buckets=max_s3_buckets,
            worker_count=s3_notification_worker_count,
            policy_scan_max_functions=s3_policy_scan_max_functions,
            notification_detail_mode=self.s3_notification_detail_mode,
        )
        self.collection_summary = LambdaCostCycleCollectionSummary(
            s3_notification_detail_mode=self.s3_notification_detail_mode,
            operational_bucket_cap=max_s3_buckets,
        )
        self._s3_notification_bucket_selector = LambdaS3NotificationBucketSelector(
            selected_regions=selected_regions,
            max_s3_buckets=max_s3_buckets,
            worker_count=s3_notification_worker_count,
            policy_scan_max_functions=s3_policy_scan_max_functions,
            notification_detail_mode=self.s3_notification_detail_mode,
        )

    def collect_functions(  # noqa: D102
        self,
        scan_period: ScanPeriod,
        *,
        s3_bucket_index: S3BucketIndexResult | None = None,
        lambda_function_inventory_by_region: (dict[str, list[LambdaFunctionInventoryRecord]] | None) = None,
    ) -> list[LambdaCostCycleRecord]:
        if lambda_function_inventory_by_region is not None:
            self.prime_function_inventory(lambda_function_inventory_by_region)
        self._collect_lambda_function_inventory()
        s3_notifications_by_function = group_s3_notifications_by_function(
            self._collect_s3_notifications(s3_bucket_index=s3_bucket_index),
        )
        result = RegionalAwsCollectionRunner(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="LambdaCostCycleRecordBuilder",
        ).collect_region_lists(
            regions=self.get_available_regions(),
            service="lambda",
            operation="BuildFunctionRecords",
            collect_region=lambda region: self._collect_functions_in_region(
                region,
                scan_period,
                s3_notifications_by_function,
            ),
        )
        return result.values

    def _collect_functions_in_region(
        self,
        region: str,
        scan_period: ScanPeriod,
        s3_notifications_by_function: dict[str, list[S3LambdaNotificationRecord]],
    ) -> list[LambdaCostCycleRecord]:
        records: list[LambdaCostCycleRecord] = []
        client = self.session.create_client(
            "lambda",
            region_name=region,
            audit_context=self.audit_context,
        )
        metric_collector = CloudWatchMetricCollector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        event_sources_by_function = self._collect_all_event_source_mappings(client)
        inventory_records = self._get_cached_function_inventory(region)
        if inventory_records is None:
            inventory_records = self._collect_function_inventory_records(
                client,
                region,
            )
        for inventory_record in inventory_records:
            function = inventory_record.function
            arn = inventory_record.function_arn
            name = inventory_record.function_name or "unknown"
            matching_s3_notifications = s3_notifications_by_function.get(arn, [])
            errors: list[str] = []
            configuration = self._get_function_configuration(client, name, errors) if matching_s3_notifications else function
            event_sources = event_sources_by_function.get(name, [])
            event_invoke_config = self._get_event_invoke_config(client, name, errors) if matching_s3_notifications or event_sources else {}
            records.append(
                LambdaCostCycleRecord(
                    function_name=name,
                    function_arn=arn,
                    account_id=self.account_id,
                    region=region,
                    runtime=optional_str(
                        configuration.get("Runtime") or function.get("Runtime"),
                    ),
                    memory_mb=optional_int_value(
                        configuration.get("MemorySize") or function.get("MemorySize"),
                    ),
                    timeout_seconds=optional_int_value(
                        configuration.get("Timeout") or function.get("Timeout"),
                    ),
                    architectures=string_list(
                        configuration.get("Architectures") or function.get("Architectures"),
                    ),
                    reserved_concurrency=None,
                    provisioned_concurrency=None,
                    event_sources=event_sources,
                    s3_notifications=matching_s3_notifications,
                    destination_config=object_mapping(
                        event_invoke_config.get("DestinationConfig", {}),
                    ),
                    environment_variables=string_mapping(
                        object_mapping(configuration.get("Environment", {})).get(
                            "Variables",
                            {},
                        ),
                    ),
                    tags={},
                    metric_summaries=[],
                    derived_metric_policy_fields_populated=False,
                    collection_errors=tuple(errors),
                    tag_evidence=LambdaTagEvidence(
                        state="not_collected",
                        limitation="Lambda tag collection was disabled by configuration.",
                    ),
                ),
            )
        metric_summaries = self._collect_metrics_for_records(
            metric_collector,
            scan_period,
            records,
        )
        enriched_records: list[LambdaCostCycleRecord] = []
        for record in records:
            enriched_record = replace(
                record,
                metric_summaries=metric_summaries.get(record.function_name, []),
            )
            if self.collect_tags:
                tag_evidence = self._list_function_tags(
                    client,
                    enriched_record.function_arn,
                )
                enriched_record = replace(
                    enriched_record,
                    tags=dict(tag_evidence.tags),
                    tag_evidence=tag_evidence,
                )
            enriched_records.append(enriched_record)
        return enriched_records

    def _collect_function_inventory_records(
        self,
        client: AuditedAwsClient,
        region: str,
    ) -> list[LambdaFunctionInventoryRecord]:
        records: list[LambdaFunctionInventoryRecord] = []
        pages = self._pagination.collect_token_pages(
            client,
            "list_functions",
            result_key="Functions",
            request_parameters={"MaxItems": 50},
            request_cursor_key="Marker",
            response_cursor_keys=("NextMarker",),
        ).pages
        for function in iter_response_rows(pages, "Functions"):
            require_response_string(function.get("FunctionArn"))
            require_response_string(function.get("FunctionName"))
            record = self._build_function_inventory_record(region, function)
            if record is not None:
                records.append(record)
        self._cache_function_inventory(region, records)
        return records

    def _collect_lambda_function_inventory(
        self,
        *,
        regions: list[str] | None = None,
    ) -> LambdaPolicyTargetCollectionResult:
        requested_regions = regions or self.get_available_regions()
        regions_to_collect = [region for region in requested_regions if self._get_cached_function_inventory(region) is None]
        if not regions_to_collect:
            return LambdaPolicyTargetCollectionResult(
                targets=self._build_policy_targets_from_cached_inventory(
                    requested_regions,
                ),
                error_count=0,
            )
        result = RegionalAwsCollectionRunner(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="LambdaFunctionInventoryCollector",
        ).collect_region_lists(
            regions=regions_to_collect,
            service="lambda",
            operation="ListFunctions",
            collect_region=self._collect_lambda_function_inventory_in_region,
        )
        return LambdaPolicyTargetCollectionResult(
            targets=self._build_policy_targets_from_cached_inventory(
                requested_regions,
            ),
            error_count=len(result.get_failed_results()),
        )

    def _collect_lambda_function_inventory_in_region(
        self,
        region: str,
    ) -> list[LambdaFunctionInventoryRecord]:
        client = self.session.create_client(
            "lambda",
            region_name=region,
            audit_context=self.audit_context,
        )
        return self._collect_function_inventory_records(client, region)

    def collect_function_inventory_by_region(  # noqa: D102
        self,
        *,
        regions: list[str] | None = None,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        requested_regions = regions or self.get_available_regions()
        self._collect_lambda_function_inventory(regions=requested_regions)
        return {region: self._get_cached_function_inventory(region) or [] for region in requested_regions}

    def prime_function_inventory(  # noqa: D102
        self,
        records_by_region: dict[str, list[LambdaFunctionInventoryRecord]],
    ) -> None:
        for region, records in records_by_region.items():
            self._cache_function_inventory(region, records)

    def _build_policy_targets_from_cached_inventory(
        self,
        regions: list[str],
    ) -> list[LambdaFunctionPolicyTarget]:
        targets: list[LambdaFunctionPolicyTarget] = []
        for region in regions:
            records = self._get_cached_function_inventory(region)
            if records is None:
                continue
            targets.extend(target for record in records if (target := record.get_policy_target()) is not None)
        return targets

    def _build_function_inventory_record(
        self,
        region: str,
        function: dict[str, object],
    ) -> LambdaFunctionInventoryRecord | None:
        arn = str(function.get("FunctionArn") or "")
        name = str(function.get("FunctionName") or function_name_from_arn(arn) or "")
        if not arn and not name:
            return None
        return LambdaFunctionInventoryRecord(
            function_name=name,
            function_arn=arn,
            region=region,
            function=dict(function),
        )

    def _cache_function_inventory(
        self,
        region: str,
        records: list[LambdaFunctionInventoryRecord],
    ) -> None:
        with self._function_inventory_lock:
            self._function_inventory_by_region[region] = list(records)

    def _get_cached_function_inventory(
        self,
        region: str,
    ) -> list[LambdaFunctionInventoryRecord] | None:
        with self._function_inventory_lock:
            records = self._function_inventory_by_region.get(region)
            if records is None:
                return None
            return list(records)

    def _get_function_configuration(
        self,
        client: AuditedAwsClient,
        function_name: str,
        errors: list[str] | None = None,
    ) -> dict[str, object]:
        try:
            response = client.get_function_configuration(FunctionName=function_name)
            response = require_response_mapping(response)
            require_response_string(response.get("FunctionName"))
        except Exception:  # noqa: BLE001
            if errors is not None:
                errors.append("GetFunctionConfiguration:UnavailableEvidence")
            return {}
        return response

    def _list_function_tags(
        self,
        client: AuditedAwsClient,
        arn: str,
    ) -> LambdaTagEvidence:
        if not arn:
            return LambdaTagEvidence(
                state="unavailable",
                limitation="Lambda function ARN was unavailable for tag collection.",
            )
        try:
            response = require_response_mapping(client.list_tags(Resource=arn))
            tags = require_response_mapping(response.get("Tags"))
        except Exception:  # noqa: BLE001
            return LambdaTagEvidence(
                state="unavailable",
                limitation="Lambda tag read failed.",
            )
        if any(not isinstance(value, str) for value in tags.values()):
            return LambdaTagEvidence(
                state="unavailable",
                limitation="Lambda tag response did not contain a valid tag mapping.",
            )
        return LambdaTagEvidence(
            state="known",
            tags={str(key): str(value) for key, value in tags.items()},
        )

    def _get_event_invoke_config(
        self,
        client: AuditedAwsClient,
        function_name: str,
        errors: list[str] | None = None,
    ) -> dict[str, object]:
        try:
            response = client.get_function_event_invoke_config(
                FunctionName=function_name,
            )
            response = require_response_mapping(response)
            if "DestinationConfig" in response:
                require_response_mapping(response["DestinationConfig"])
            else:
                require_response_string(response.get("FunctionArn"))
        except Exception as exc:  # noqa: BLE001
            if errors is not None and get_aws_error_code(exc) != "ResourceNotFoundException":
                errors.append("GetFunctionEventInvokeConfig:UnavailableEvidence")
            return {}
        return response
