from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.evidence.cost.explorer.keys import (
    CostExplorerEvidenceCacheKeyBuilder,
    CostExplorerEvidenceLabelBuilder,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition

SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID = "unio-collector-shared-cost-explorer-daily-costs"
SHARED_COST_EXPLORER_DAILY_COST_API_CALLS = ("ce:GetCostAndUsage",)
SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS: dict[
    tuple[str, ...],
    frozenset[str],
] = {
    ("SERVICE",): frozenset(
        {
            "account-cost-risk-signal-review",
            "cost-spike-analysis",
        },
    ),
    ("SERVICE", "REGION"): frozenset(
        {
            "api-gateway-cost-review",
            "athena-query-efficiency-review",
            "backup-retention-review",
            "bedrock-cost-review",
            "cloudtrail-cost-governance-review",
            "config-cost-governance-review",
            "dynamodb-cost-governance-review",
            "ecs-cost-governance-review",
            "eks-cost-risk-review",
            "elasticache-cost-review",
            "glue-job-crawler-cost-review",
            "guardduty-cost-governance-review",
            "kms-cost-governance-review",
            "opensearch-cost-review",
            "redshift-cost-review",
            "s3-incomplete-multipart-review",
            "s3-lifecycle-cost-review",
            "s3-versioning-and-replication-review",
            "sagemaker-cost-review",
            "secrets-manager-cost-governance-review",
            "securityhub-inspector-macie-cost-review",
            "waf-cost-governance-review",
        },
    ),
    ("SERVICE", "USAGE_TYPE"): frozenset(
        {
            "athena-query-efficiency-review",
            "bedrock-cost-review",
            "data-transfer-cost-review",
            "glue-job-crawler-cost-review",
            "nat-gateway-cost-review",
            "sagemaker-cost-review",
        },
    ),
}


class CostExplorerEvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def build_cost_explorer_cache_keys(self) -> CostExplorerEvidenceCacheKeyBuilder:  # noqa: D102
        return CostExplorerEvidenceCacheKeyBuilder(
            account_id=self.runner.runtime_state.account_id,
        )

    def build_cost_explorer_labels(self) -> CostExplorerEvidenceLabelBuilder:  # noqa: D102
        return CostExplorerEvidenceLabelBuilder()

    def collect_cached_service_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="cost_explorer_service_costs",
            label=self.build_cost_explorer_labels().build_service_costs_label(),
        )
        context = self.runner.create_audit_context(
            definition,
            "CostExplorerCollector",
        )
        collector = self.runner.create_cost_explorer_collector(context)
        runtime_state = self.runner.runtime_state
        period = runtime_state.config.scan_period
        access = runtime_state.cache.get_or_load_with_status(
            "cost_explorer_service_costs",
            self.build_cost_explorer_cache_keys().build_service_costs_key(
                period=period,
            ),
            lambda: collector.collect_service_costs(scan_period=period),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="cost_explorer_service_costs",
            label=self.build_cost_explorer_labels().build_service_costs_label(),
            access_status=access.status,
        )
        return access.value

    def collect_cached_daily_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        context = self.runner.create_audit_context(
            definition,
            "CostExplorerCollector",
        )
        return self.collect_cached_daily_costs_with_context(
            context,
            group_keys=group_keys,
        )

    def collect_cached_daily_costs_with_context(  # noqa: D102
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        self.raise_if_deadline_expired(
            audit_context.scanner_id,
            namespace="cost_explorer_daily_costs",
            label=self.build_cost_explorer_labels().build_daily_costs_label(
                group_keys=group_keys,
            ),
        )
        collector = self.runner.create_cost_explorer_collector(audit_context)
        runtime_state = self.runner.runtime_state
        period = runtime_state.config.scan_period
        access = runtime_state.cache.get_or_load_with_status(
            "cost_explorer_daily_costs",
            self.build_cost_explorer_cache_keys().build_daily_costs_key(
                period=period,
                group_keys=group_keys,
            ),
            lambda: collector.collect_daily_costs(
                scan_period=period,
                group_keys=group_keys,
            ),
            access_policy=self.build_cache_access_policy(
                consumer_id=audit_context.scanner_id,
            ),
        )
        self.add_cached_evidence_note_for_scanner(
            audit_context.scanner_id,
            namespace="cost_explorer_daily_costs",
            label=self.build_cost_explorer_labels().build_daily_costs_label(
                group_keys=group_keys,
            ),
            access_status=access.status,
        )
        return list(access.value)
