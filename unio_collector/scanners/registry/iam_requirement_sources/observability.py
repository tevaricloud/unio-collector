from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CLOUDWATCH_IDLE_LOG_REVIEW_EVIDENCE = ("CloudWatch Log Group",)

CLOUDWATCH_LOG_COST_AND_RELEVANCE_REVIEW_EVIDENCE = ("CloudWatch Log Group",)

CLOUDWATCH_LOG_GROUPS_WITHOUT_RETENTION_EVIDENCE = ("CloudWatch Log Group",)

XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "X-Ray group",
    "X-Ray sampling rule",
    "X-Ray sampling statistic summary",
)

OBSERVABILITY_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "cloudwatch-idle-log-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "logs:DescribeLogGroups",
                "required",
                "CloudWatch idle log review requires logs:DescribeLogGroups to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_IDLE_LOG_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="logs:DescribeLogGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "CloudWatch idle log review requires cloudwatch:GetMetricData to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_IDLE_LOG_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "CloudWatch idle log review requires cloudwatch:GetMetricStatistics to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_IDLE_LOG_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "cloudwatch-log-cost-and-relevance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "logs:DescribeLogGroups",
                "required",
                "CloudWatch log cost and relevance review requires logs:DescribeLogGroups to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_LOG_COST_AND_RELEVANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="logs:DescribeLogGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "CloudWatch log cost and relevance review requires cloudwatch:GetMetricData to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_LOG_COST_AND_RELEVANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "CloudWatch log cost and relevance review requires cloudwatch:GetMetricStatistics to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_LOG_COST_AND_RELEVANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "cloudwatch-log-groups-without-retention": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "logs:DescribeLogGroups",
                "required",
                "CloudWatch Log Groups without retention requires logs:DescribeLogGroups to collect read-only CloudWatch Log Group evidence.",
                chargeable=False,
                evidence_categories=CLOUDWATCH_LOG_GROUPS_WITHOUT_RETENTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="logs:DescribeLogGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "xray-tracing-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "xray:GetGroups",
                "required",
                "X-Ray tracing cost governance review requires xray:GetGroups to collect read-only X-Ray group, X-Ray sampling "
                "rule, X-Ray sampling statistic summary evidence.",
                chargeable=False,
                evidence_categories=XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="xray:GetGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "xray:GetSamplingRules",
                "required",
                "X-Ray tracing cost governance review requires xray:GetSamplingRules to collect read-only X-Ray group, "
                "X-Ray sampling rule, X-Ray sampling statistic summary evidence.",
                chargeable=False,
                evidence_categories=XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="xray:GetSamplingRules is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "xray:GetSamplingStatisticSummaries",
                "required",
                "X-Ray tracing cost governance review requires xray:GetSamplingStatisticSummaries to "
                "collect read-only X-Ray group, X-Ray sampling rule, X-Ray sampling statistic summary "
                "evidence.",
                chargeable=False,
                evidence_categories=XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="xray:GetSamplingStatisticSummaries is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "xray:GetEncryptionConfig",
                "required",
                "X-Ray tracing cost governance review requires xray:GetEncryptionConfig to collect read-only X-Ray "
                "group, X-Ray sampling rule, X-Ray sampling statistic summary evidence.",
                chargeable=False,
                evidence_categories=XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="xray:GetEncryptionConfig is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "X-Ray tracing cost governance review requires ce:GetCostAndUsage to collect read-only X-Ray group, X-Ray "
                "sampling rule, X-Ray sampling statistic summary evidence.",
                chargeable=False,
                evidence_categories=XRAY_TRACING_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
