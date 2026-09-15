# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any, TypeVar

from unio_collector.aws.audit_cost.guardduty.record import (
    GuardDutyCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.inventory.helpers import (
    WAF_ASSOCIATION_SKIP_REASON_DETAIL_MODE,
)
from unio_collector.aws.audit_cost.security_services.record import (
    SecurityHubInspectorMacieCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.waf.record import WafCostGovernanceRecord
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    record_collection_results,
)

AuditRecordT = TypeVar("AuditRecordT")


class SecurityAuditCollectionMixin:  # noqa: D101
    def _collect_cloudfront_waf_task(self) -> list[Any]:
        executor = AwsCollectionExecutor(
            max_workers=self.session.runtime_config.max_workers,
        )
        task = AwsCollectionTask(
            name=(f"AuditCostInventoryCollector:wafv2:{self._get_waf_operation_summary()}:global"),
            scanner_id=self.audit_context.scanner_id,
            collector_id="AuditCostInventoryCollector",
            account_id=self.account_id,
            region="global",
            service="wafv2",
            operation=self._get_waf_operation_summary(),
            collect=self._collect_cloudfront_waf_records,
        )
        results = executor.run([task])
        record_collection_results(self.session, results)
        return results

    def _collect_cloudfront_waf_records(self) -> list[WafCostGovernanceRecord]:
        client = self.session.create_client(
            "wafv2",
            region_name="us-east-1",
            audit_context=self.audit_context,
        )
        return [self._build_waf_record(client, region="global", scope="CLOUDFRONT")]

    def _build_waf_record(
        self,
        client: Any,  # noqa: ANN401
        *,
        region: str,
        scope: str,
    ) -> WafCostGovernanceRecord:
        web_acls = self._collect_web_acls(client, scope)
        web_acl_details: list[dict[str, Any]] = []
        associated_resource_count = 0
        associated_resource_types: set[str] = set()
        permission_errors: list[str] = []
        collect_associations = self.waf_collection_options.should_collect_association_metadata()
        for acl in web_acls:
            name = str(acl.get("Name") or "")
            acl_id = str(acl.get("Id") or "")
            arn = str(acl.get("ARN") or "")
            if name and acl_id:
                detail = self._safe_call(
                    client,
                    "get_web_acl",
                    {"Name": name, "Scope": scope, "Id": acl_id},
                    permission_errors,
                )
                if detail:
                    web_acl_details.append(detail.get("WebACL", detail))
            if arn and collect_associations:
                resources = self._safe_call(
                    client,
                    "list_resources_for_web_acl",
                    {"WebACLArn": arn},
                    permission_errors,
                )
                if resources:
                    resource_arns = resources.get("ResourceArns", [])
                    if isinstance(resource_arns, list):
                        associated_resource_count += len(resource_arns)
                        associated_resource_types.update(
                            self._get_associated_resource_types(resource_arns),
                        )
        rules = [rule for detail in web_acl_details for rule in detail.get("Rules", []) or [] if isinstance(rule, dict)]
        visibility_configs = [
            config
            for config in [detail.get("VisibilityConfig") for detail in web_acl_details if isinstance(detail.get("VisibilityConfig"), dict)]
            if isinstance(config, dict)
        ]
        visibility_configs.extend(
            config for config in [rule.get("VisibilityConfig") for rule in rules if isinstance(rule.get("VisibilityConfig"), dict)] if isinstance(config, dict)
        )
        return WafCostGovernanceRecord(
            account_id=self.account_id,
            region=region,
            scope=scope,
            web_acl_count=len(web_acls),
            web_acl_capacity_total=sum(self._get_int(detail.get("Capacity")) for detail in web_acl_details),
            managed_rule_group_count=self._count_managed_rule_groups(rules),
            rate_based_rule_count=self._count_rate_based_rules(rules),
            captcha_rule_count=self._count_waf_action_rules(rules, "CAPTCHA"),
            challenge_rule_count=self._count_waf_action_rules(rules, "CHALLENGE"),
            count_action_rule_count=self._count_waf_action_rules(rules, "COUNT"),
            allow_action_rule_count=self._count_waf_action_rules(rules, "ALLOW"),
            block_action_rule_count=self._count_waf_action_rules(rules, "BLOCK"),
            default_allow_acl_count=self._count_waf_default_actions(
                web_acl_details,
                "ALLOW",
            ),
            default_block_acl_count=self._count_waf_default_actions(
                web_acl_details,
                "BLOCK",
            ),
            rule_count=len(rules),
            cloudwatch_metrics_enabled_count=sum(1 for config in visibility_configs if bool(config.get("CloudWatchMetricsEnabled"))),
            sampled_requests_enabled_count=sum(1 for config in visibility_configs if bool(config.get("SampledRequestsEnabled"))),
            associated_resource_count=associated_resource_count,
            association_detail_mode=(self.waf_collection_options.association_detail_mode),
            association_metadata_collected=collect_associations,
            association_skip_reason=(None if collect_associations else WAF_ASSOCIATION_SKIP_REASON_DETAIL_MODE),
            associated_resource_types=sorted(associated_resource_types),
            rule_action_types=self._get_waf_rule_action_types(rules),
            managed_rule_group_names=self._get_managed_rule_group_names(rules),
            sample_rate_limits=self._get_waf_rate_limits(rules),
            sample_web_acl_names=[str(acl.get("Name")) for acl in web_acls[:10] if acl.get("Name")],
            permission_errors=permission_errors,
        )

    def _get_waf_operation_summary(self) -> str:
        if self.waf_collection_options.should_collect_association_metadata():
            return "ListWebACLs+GetWebACL+ListResourcesForWebACL"
        return "ListWebACLs+GetWebACL"

    def _collect_guardduty_record(
        self,
        region: str,
    ) -> list[GuardDutyCostGovernanceRecord]:
        client = self.session.create_client(
            "guardduty",
            region_name=region,
            audit_context=self.audit_context,
        )
        permission_errors: list[str] = []
        response = self._safe_call(client, "list_detectors", {}, permission_errors)
        detector_ids = response.get("DetectorIds", []) if response else []
        if not isinstance(detector_ids, list):
            detector_ids = []
        detector_details = [
            detail
            for detector_id in detector_ids
            if isinstance(detector_id, str)
            for detail in [
                self._safe_call(
                    client,
                    "get_detector",
                    {"DetectorId": detector_id},
                    permission_errors,
                ),
            ]
            if detail
        ]
        enabled_features = self._get_enabled_guardduty_features(detector_details)
        disabled_features = self._get_disabled_guardduty_features(detector_details)
        return [
            GuardDutyCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                detector_count=len(detector_ids),
                enabled_detector_count=sum(1 for detail in detector_details if str(detail.get("Status") or "").upper() == "ENABLED"),
                enabled_feature_count=len(enabled_features),
                disabled_feature_count=len(disabled_features),
                feature_status_counts=self._get_guardduty_feature_status_counts(
                    detector_details,
                ),
                finding_publishing_frequencies=sorted(
                    {str(detail.get("FindingPublishingFrequency")) for detail in detector_details if detail.get("FindingPublishingFrequency")},
                ),
                detector_status_values=self._get_guardduty_detector_status_values(
                    detector_details,
                ),
                enabled_feature_names=enabled_features[:20],
                sample_disabled_feature_names=disabled_features[:20],
                sample_detector_ids=[str(detector_id) for detector_id in detector_ids[:10]],
                permission_errors=permission_errors,
            ),
        ]

    def _collect_securityhub_inspector_macie_record(
        self,
        region: str,
    ) -> list[SecurityHubInspectorMacieCostGovernanceRecord]:
        permission_errors: list[str] = []
        securityhub_summary = self._collect_securityhub_summary(
            region,
            permission_errors,
        )
        inspector_summary = self._collect_inspector_summary(region, permission_errors)
        macie_summary = self._collect_macie_summary(region, permission_errors)
        return [
            SecurityHubInspectorMacieCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                securityhub_enabled=securityhub_summary["enabled"],
                securityhub_standard_count=securityhub_summary["standard_count"],
                securityhub_ready_standard_count=(securityhub_summary["ready_standard_count"]),
                securityhub_non_ready_standard_count=(securityhub_summary["non_ready_standard_count"]),
                securityhub_standard_statuses=securityhub_summary["standard_statuses"],
                sample_securityhub_standard_arns=securityhub_summary["sample_standard_arns"],
                inspector_enabled=self._is_enabled_status(inspector_summary["status"]),
                inspector_status=inspector_summary["status"],
                inspector_resource_statuses=inspector_summary["resource_statuses"],
                macie_enabled=self._is_enabled_status(macie_summary["status"]),
                macie_status=macie_summary["status"],
                macie_finding_publishing_frequency=macie_summary["finding_publishing_frequency"],
                macie_classification_job_count=macie_summary["job_count"],
                macie_job_statuses=macie_summary["job_statuses"],
                sample_macie_job_ids=macie_summary["sample_job_ids"],
                macie_job_status_counts=macie_summary["job_status_counts"],
                derived_policy_fields_populated=False,
                permission_errors=permission_errors,
            ),
        ]
