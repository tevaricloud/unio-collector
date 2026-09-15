# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.audit_cost.cloudtrail.record import (
    CloudTrailCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.cloudtrail.selector_evidence import (
    CloudTrailSelectorEvidence,
)
from unio_collector.aws.audit_cost.cloudtrail.store_evidence import (
    CloudTrailEventDataStoreEvidence,
)
from unio_collector.aws.audit_cost.config.record import ConfigCostGovernanceRecord
from unio_collector.aws.audit_cost.inventory.helpers import (
    CONFIG_RULE_DETAIL_SKIP_REASON_DETAIL_MODE,
)

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.waf.record import WafCostGovernanceRecord

AuditRecordT = TypeVar("AuditRecordT")


class PrimaryAuditCollectionMixin:  # noqa: D101
    def _collect_cloudtrail_record(
        self,
        region: str,
    ) -> list[CloudTrailCostGovernanceRecord]:
        client = self.session.create_client(
            "cloudtrail",
            region_name=region,
            audit_context=self.audit_context,
        )
        response = client.describe_trails(includeShadowTrails=False)
        trails = response.get("trailList", [])
        if not isinstance(trails, list):
            trails = []
        statuses: list[dict[str, Any]] = []
        event_selectors: list[dict[str, Any]] = []
        insight_selectors: list[dict[str, Any]] = []
        permission_errors: list[str] = []
        event_data_stores = self._collect_cloudtrail_event_data_stores(
            client,
            permission_errors,
        )
        for trail in trails:
            trail_name = str(trail.get("Name") or "")
            if not trail_name:
                continue
            status = self._safe_call(
                client,
                "get_trail_status",
                {"Name": trail_name},
                permission_errors,
            )
            if status:
                statuses.append({**status, "__TrailName": trail_name})
            selectors = self._safe_call(
                client,
                "get_event_selectors",
                {"TrailName": trail_name},
                permission_errors,
            )
            if selectors:
                event_selectors.append({**selectors, "__TrailName": trail_name})
            insights = self._safe_call(
                client,
                "get_insight_selectors",
                {"TrailName": trail_name},
                permission_errors,
            )
            if insights:
                insight_selectors.append(insights)
        raw_selectors = self._build_cloudtrail_selector_evidence(event_selectors)
        raw_event_data_stores = self._build_cloudtrail_store_evidence(
            event_data_stores,
        )
        return [
            CloudTrailCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                trail_count=len(trails),
                multi_region_trail_count=sum(1 for trail in trails if trail.get("IsMultiRegionTrail")),
                organization_trail_count=sum(1 for trail in trails if trail.get("IsOrganizationTrail")),
                logging_trail_count=sum(1 for status in statuses if status.get("IsLogging")),
                logging_stopped_trail_count=sum(1 for status in statuses if status.get("IsLogging") is False),
                trail_status_error_count=self._count_cloudtrail_status_errors(statuses),
                trails_with_data_events=self._count_trails_with_data_events(
                    event_selectors,
                ),
                data_event_selector_count=sum(self._count_data_event_selectors(selectors) for selectors in event_selectors),
                advanced_event_selector_count=sum(len(selectors.get("AdvancedEventSelectors", []) or []) for selectors in event_selectors),
                advanced_field_selector_count=sum(self._count_advanced_field_selectors(selectors) for selectors in event_selectors),
                data_resource_value_count=sum(self._count_data_resource_values(selectors) for selectors in event_selectors),
                insight_selector_count=sum(len(selectors.get("InsightSelectors", []) or []) for selectors in insight_selectors),
                trails_with_insight_selectors=sum(1 for selectors in insight_selectors if selectors.get("InsightSelectors")),
                trails_with_management_events=(self._count_trails_with_management_events(event_selectors)),
                logging_trails_with_management_events=(
                    self._count_logging_trails_with_management_events(
                        event_selectors,
                        statuses,
                    )
                ),
                event_data_store_count=len(event_data_stores),
                event_data_store_max_retention_days=(self._get_max_event_data_store_retention_days(event_data_stores)),
                event_data_store_advanced_selector_count=(self._count_event_data_store_advanced_selectors(event_data_stores)),
                log_file_validation_enabled_count=sum(1 for trail in trails if trail.get("LogFileValidationEnabled")),
                cloudwatch_logs_delivery_count=sum(1 for trail in trails if trail.get("CloudWatchLogsLogGroupArn")),
                kms_encrypted_trail_count=sum(1 for trail in trails if trail.get("KmsKeyId")),
                s3_destination_count=len(
                    {str(trail.get("S3BucketName")) for trail in trails if trail.get("S3BucketName")},
                ),
                sns_notification_count=len(
                    {str(trail.get("SnsTopicARN") or trail.get("SnsTopicName")) for trail in trails if trail.get("SnsTopicARN") or trail.get("SnsTopicName")},
                ),
                management_event_selector_count=sum(self._count_management_event_selectors(selectors) for selectors in event_selectors),
                data_resource_types=self._get_data_resource_types(event_selectors),
                selector_read_write_types=self._get_selector_read_write_types(
                    event_selectors,
                ),
                advanced_selector_names=self._get_advanced_selector_names(
                    event_selectors,
                ),
                sample_data_resource_values=self._get_sample_data_resource_values(
                    event_selectors,
                ),
                sample_event_data_store_names=(self._get_sample_event_data_store_names(event_data_stores)),
                event_data_store_statuses=self._get_event_data_store_statuses(
                    event_data_stores,
                ),
                sample_s3_bucket_names=sorted(
                    {str(trail.get("S3BucketName")) for trail in trails if trail.get("S3BucketName")},
                )[:10],
                sample_cloudwatch_log_group_arns=sorted(
                    {str(trail.get("CloudWatchLogsLogGroupArn")) for trail in trails if trail.get("CloudWatchLogsLogGroupArn")},
                )[:10],
                sample_kms_key_ids=sorted(
                    {str(trail.get("KmsKeyId")) for trail in trails if trail.get("KmsKeyId")},
                )[:10],
                sample_home_regions=sorted(
                    {str(trail.get("HomeRegion")) for trail in trails if trail.get("HomeRegion")},
                )[:10],
                sample_trail_names=[str(trail.get("Name")) for trail in trails[:10] if trail.get("Name")],
                sample_management_event_trail_names=(self._get_management_event_trail_names(event_selectors)),
                raw_selectors=raw_selectors,
                raw_event_data_stores=raw_event_data_stores,
                derived_policy_fields_populated=False,
                permission_errors=permission_errors,
            ),
        ]

    def _build_cloudtrail_selector_evidence(
        self,
        selector_responses: list[dict[str, Any]],
    ) -> list[CloudTrailSelectorEvidence]:
        evidence: list[CloudTrailSelectorEvidence] = []
        for response in selector_responses:
            trail_name = str(response.get("__TrailName") or "")
            for selector in response.get("EventSelectors", []) or []:
                if not isinstance(selector, dict):
                    continue
                resource_types: list[str] = []
                resource_values: list[str] = []
                for resource in selector.get("DataResources", []) or []:
                    if not isinstance(resource, dict):
                        continue
                    if resource.get("Type"):
                        resource_types.append(str(resource["Type"]))
                    values = resource.get("Values", [])
                    if isinstance(values, list):
                        resource_values.extend(str(value) for value in values[:1000])
                evidence.append(
                    CloudTrailSelectorEvidence(
                        trail_name=trail_name,
                        selector_kind="basic",
                        read_write_type=self._optional_string(
                            selector.get("ReadWriteType"),
                        ),
                        include_management_events=bool(
                            selector.get("IncludeManagementEvents", True),
                        ),
                        exclude_management_event_sources=sorted(
                            str(value)
                            for value in selector.get(
                                "ExcludeManagementEventSources",
                                [],
                            )
                            or []
                        ),
                        resource_types=sorted(dict.fromkeys(resource_types)),
                        resource_values=resource_values,
                    ),
                )
            evidence.extend(
                self._build_advanced_selector_evidence(
                    selector,
                    trail_name=trail_name,
                )
                for selector in response.get("AdvancedEventSelectors", []) or []
                if isinstance(selector, dict)
            )
        return evidence

    def _build_cloudtrail_store_evidence(
        self,
        stores: list[dict[str, Any]],
    ) -> list[CloudTrailEventDataStoreEvidence]:
        evidence: list[CloudTrailEventDataStoreEvidence] = []
        for store in stores:
            identifier = str(store.get("EventDataStoreArn") or store.get("Name") or "")
            selectors = [
                self._build_advanced_selector_evidence(selector) for selector in store.get("AdvancedEventSelectors", []) or [] if isinstance(selector, dict)
            ]
            retention = store.get("RetentionPeriod")
            evidence.append(
                CloudTrailEventDataStoreEvidence(
                    identifier=identifier,
                    name=self._optional_string(store.get("Name")),
                    status=self._optional_string(store.get("Status")),
                    retention_period_days=(retention if isinstance(retention, int) else None),
                    advanced_selectors=selectors,
                ),
            )
        return evidence

    def _build_advanced_selector_evidence(
        self,
        selector: dict[str, Any],
        *,
        trail_name: str = "",
    ) -> CloudTrailSelectorEvidence:
        conditions: list[dict[str, object]] = []
        event_categories: list[str] = []
        for field_selector in selector.get("FieldSelectors", []) or []:
            if not isinstance(field_selector, dict):
                continue
            condition: dict[str, object] = {}
            field_name = field_selector.get("Field")
            if field_name:
                condition["field"] = str(field_name)
            for provider_key in (
                "Equals",
                "StartsWith",
                "EndsWith",
                "NotEquals",
                "NotStartsWith",
                "NotEndsWith",
            ):
                values = field_selector.get(provider_key)
                if isinstance(values, list):
                    normalized = [str(value) for value in values]
                    condition[provider_key] = normalized
                    if field_name == "eventCategory" and provider_key == "Equals":
                        event_categories.extend(normalized)
            conditions.append(condition)
        return CloudTrailSelectorEvidence(
            trail_name=trail_name,
            selector_kind="advanced",
            selector_name=self._optional_string(selector.get("Name")),
            event_categories=sorted(dict.fromkeys(event_categories)),
            field_conditions=conditions,
        )

    def _optional_string(self, value: object) -> str | None:
        return str(value) if value is not None and str(value) else None

    def _collect_config_record(
        self,
        region: str,
    ) -> list[ConfigCostGovernanceRecord]:
        client = self.session.create_client(
            "config",
            region_name=region,
            audit_context=self.audit_context,
        )
        recorders = self._collect_config_recorders(client)
        permission_errors: list[str] = []
        recorder_statuses = self._collect_config_recorder_statuses(
            client,
            permission_errors,
        )
        delivery_channels = self._collect_delivery_channels(client)
        config_rules: list[dict[str, Any]] = []
        conformance_packs: list[dict[str, Any]] = []
        if self.config_collection_options.should_collect_rule_metadata():
            config_rules = self._collect_config_rules(client)
            conformance_packs = self._collect_conformance_packs(client)
        else:
            permission_errors.extend(
                [
                    (f"describe_config_rules:{CONFIG_RULE_DETAIL_SKIP_REASON_DETAIL_MODE}"),
                    (f"describe_conformance_packs:{CONFIG_RULE_DETAIL_SKIP_REASON_DETAIL_MODE}"),
                ],
            )
        return [
            ConfigCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                recorder_count=len(recorders),
                recording_enabled_count=sum(1 for status in recorder_statuses if self._is_recording(status)),
                recording_stopped_count=sum(1 for status in recorder_statuses if not self._is_recording(status)),
                delivery_channel_count=len(delivery_channels),
                delivery_s3_bucket_count=len(
                    {str(channel.get("s3BucketName")) for channel in delivery_channels if channel.get("s3BucketName")},
                ),
                delivery_sns_topic_count=len(
                    {str(channel.get("snsTopicARN")) for channel in delivery_channels if channel.get("snsTopicARN")},
                ),
                all_supported_recording_count=sum(
                    1
                    for recorder in recorders
                    if recorder.get("recordingGroup", {}).get(
                        "allSupported",
                    )
                ),
                include_global_resource_types_count=sum(
                    1
                    for recorder in recorders
                    if recorder.get("recordingGroup", {}).get(
                        "includeGlobalResourceTypes",
                    )
                ),
                config_rule_count=len(config_rules),
                aws_managed_rule_count=sum(1 for rule in config_rules if self._is_aws_managed_config_rule(rule)),
                custom_rule_count=sum(1 for rule in config_rules if not self._is_aws_managed_config_rule(rule)),
                periodic_rule_count=sum(1 for rule in config_rules if self._has_periodic_trigger(rule)),
                change_triggered_rule_count=sum(1 for rule in config_rules if self._has_change_trigger(rule)),
                conformance_pack_count=len(conformance_packs),
                targeted_resource_type_count=sum(len(self._get_recorded_resource_types(recorder)) for recorder in recorders),
                excluded_resource_type_count=sum(len(self._get_excluded_resource_types(recorder)) for recorder in recorders),
                continuous_recording_count=sum(1 for recorder in recorders if self._get_config_recording_frequency(recorder) == "CONTINUOUS"),
                daily_recording_count=sum(1 for recorder in recorders if self._get_config_recording_frequency(recorder) == "DAILY"),
                recorder_last_error_count=sum(1 for status in recorder_statuses if status.get("lastErrorCode") or status.get("lastErrorMessage")),
                recording_strategy_types=self._get_recording_strategy_types(recorders),
                recording_frequency_values=(self._get_config_recording_frequency_values(recorders)),
                delivery_frequency_values=(self._get_config_delivery_frequency_values(delivery_channels)),
                recorder_last_status_values=(
                    self._get_config_recorder_last_status_values(
                        recorder_statuses,
                    )
                ),
                sample_recorded_resource_types=(self._get_sample_recorded_resource_types(recorders)),
                sample_excluded_resource_types=(self._get_sample_excluded_resource_types(recorders)),
                sample_recorder_names=[str(recorder.get("name")) for recorder in recorders[:10] if recorder.get("name")],
                sample_delivery_channel_names=[str(channel.get("name")) for channel in delivery_channels[:10] if channel.get("name")],
                sample_rule_names=[str(rule.get("ConfigRuleName")) for rule in config_rules[:10] if rule.get("ConfigRuleName")],
                sample_conformance_pack_names=[str(pack.get("ConformancePackName")) for pack in conformance_packs[:10] if pack.get("ConformancePackName")],
                permission_errors=permission_errors,
            ),
        ]

    def _collect_regional_waf_records(
        self,
        region: str,
    ) -> list[WafCostGovernanceRecord]:
        client = self.session.create_client(
            "wafv2",
            region_name=region,
            audit_context=self.audit_context,
        )
        return [self._build_waf_record(client, region=region, scope="REGIONAL")]
