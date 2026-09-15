from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.service.usage.decision import (
    ServiceUsagePrecheckDecision,
)
from unio_collector.scan_workflow.service.usage.rule import ServiceUsagePrecheckRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta

SERVICE_USAGE_PRECHECK_SCANNERS: dict[str, tuple[str, ...]] = {
    "api-gateway-cost-review": ("Amazon API Gateway",),
    "athena-query-efficiency-review": ("Amazon Athena",),
    "backup-retention-review": ("AWS Backup",),
    "bedrock-cost-review": ("Amazon Bedrock",),
    "cloudfront-origin-cost-review": ("Amazon CloudFront",),
    "cloudtrail-cost-governance-review": ("AWS CloudTrail",),
    "config-cost-governance-review": ("AWS Config",),
    "dynamodb-cost-governance-review": ("Amazon DynamoDB",),
    "ecs-cost-governance-review": (
        "Amazon Elastic Container Service",
        "Amazon ECS",
        "AWS Fargate",
    ),
    "eks-cost-risk-review": (
        "Amazon Elastic Container Service for Kubernetes",
        "Amazon Elastic Kubernetes Service",
        "Amazon EKS",
    ),
    "elasticache-cost-review": ("Amazon ElastiCache",),
    "glue-job-crawler-cost-review": ("AWS Glue",),
    "guardduty-cost-governance-review": ("Amazon GuardDuty",),
    "kms-cost-governance-review": ("AWS Key Management Service", "AWS KMS"),
    "lambda-cost-cycle-risk-review": ("AWS Lambda", "Amazon Lambda"),
    "load-balancer-idle-review": ("Elastic Load Balancing",),
    "opensearch-cost-review": (
        "Amazon OpenSearch Service",
        "Amazon Elasticsearch Service",
    ),
    "redshift-cost-review": ("Amazon Redshift",),
    "route53-cost-governance-review": ("Amazon Route 53",),
    "rds-snapshot-retention-review": (
        "Amazon Relational Database Service",
        "Amazon RDS",
    ),
    "rds-utilization-review": (
        "Amazon Relational Database Service",
        "Amazon RDS",
    ),
    "s3-lifecycle-cost-review": (
        "Amazon Simple Storage Service",
        "Amazon S3",
    ),
    "s3-versioning-and-replication-review": (
        "Amazon Simple Storage Service",
        "Amazon S3",
    ),
    "s3-incomplete-multipart-review": (
        "Amazon Simple Storage Service",
        "Amazon S3",
    ),
    "sagemaker-cost-review": ("Amazon SageMaker",),
    "secrets-manager-cost-governance-review": (
        "AWS Secrets Manager",
        "Amazon Secrets Manager",
    ),
    "securityhub-inspector-macie-cost-review": (
        "AWS Security Hub",
        "Amazon Inspector",
        "Amazon Macie",
    ),
    "lightsail-cost-governance-review": ("Amazon Lightsail",),
    "sns-cost-governance-review": (
        "Amazon Simple Notification Service",
        "Amazon SNS",
    ),
    "step-functions-cost-governance-review": ("AWS Step Functions",),
    "sqs-lambda-polling-cost-review": (
        "AWS Lambda",
        "Amazon Lambda",
        "Amazon Simple Queue Service",
        "Amazon SQS",
    ),
    "waf-cost-governance-review": ("AWS WAF", "AWS WAFV2"),
    "xray-tracing-cost-governance-review": (
        "AWS X-Ray",
        "AWS XRay",
        "Amazon X-Ray",
    ),
}


SERVICE_USAGE_PRECHECK_RULES: dict[str, ServiceUsagePrecheckRule] = {
    scanner_id: ServiceUsagePrecheckRule(service_patterns=patterns) for scanner_id, patterns in SERVICE_USAGE_PRECHECK_SCANNERS.items()
}


AUDIT_GOVERNANCE_METADATA_SCANNER_IDS = (
    "cloudtrail-cost-governance-review",
    "config-cost-governance-review",
    "guardduty-cost-governance-review",
    "securityhub-inspector-macie-cost-review",
    "waf-cost-governance-review",
)


def build_audit_governance_no_spend_reason(scanner_id: str) -> str:  # noqa: D103
    scanner_label = scanner_id.replace("-", " ")
    return (
        "Cost Explorer showed no matching service spend, but "
        f"{scanner_label} still ran because audit and security governance "
        "metadata can be useful even when current-period spend is absent or "
        "recorded under another service line."
    )


for audit_scanner_id in AUDIT_GOVERNANCE_METADATA_SCANNER_IDS:
    SERVICE_USAGE_PRECHECK_RULES[audit_scanner_id] = ServiceUsagePrecheckRule(
        service_patterns=SERVICE_USAGE_PRECHECK_SCANNERS[audit_scanner_id],
        require_billing_match_to_run=False,
        no_spend_run_reason=build_audit_governance_no_spend_reason(
            audit_scanner_id,
        ),
    )

SERVICE_USAGE_PRECHECK_RULES["ecs-cost-governance-review"] = ServiceUsagePrecheckRule(
    service_patterns=SERVICE_USAGE_PRECHECK_SCANNERS["ecs-cost-governance-review"],
    require_billing_match_to_run=False,
    no_spend_run_reason=(
        "Cost Explorer showed no matching ECS or Fargate service spend, but ECS "
        "metadata collection still ran because EC2-backed ECS services can have "
        "supporting cost recorded under EC2 rather than ECS."
    ),
)


class ServiceUsagePrecheckPolicy:
    """Decide whether service-specific scanners should run for this billing window."""

    def __init__(  # noqa: D107
        self,
        *,
        enabled: bool,
        force_run: bool,
    ) -> None:
        self.enabled = enabled
        self.force_run = force_run

    def should_run(
        self,
        scanner_id: str,
        service_deltas: Iterable[ServiceSpendDelta],
    ) -> ServiceUsagePrecheckDecision:
        """Decide whether a service-specific scanner should run."""
        rule = SERVICE_USAGE_PRECHECK_RULES.get(scanner_id)
        patterns = rule.service_patterns if rule else ()
        if not patterns:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                reason="No service-usage precheck is configured for this scanner.",
                precheck_mode="not_configured",
                billing_match_required_to_run=False,
            )
        if not self.enabled:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                configured_service_patterns=patterns,
                reason="Service-usage prechecks are disabled by configuration.",
                precheck_mode="disabled",
                billing_match_required_to_run=False,
            )
        if self.force_run:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                configured_service_patterns=patterns,
                reason="Service scanners were forced to run for this scan.",
                precheck_mode="forced",
                billing_match_required_to_run=False,
            )

        deltas = tuple(service_deltas)
        if not deltas:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                configured_service_patterns=patterns,
                reason=("Service-usage precheck did not run because service-level Cost Explorer baseline data was unavailable."),
                precheck_mode="cost_explorer_unavailable",
                billing_match_required_to_run=False,
            )

        matched_services = self._find_matching_current_spend_services(
            patterns,
            deltas,
        )
        if matched_services:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                matched_services=matched_services,
                configured_service_patterns=patterns,
                reason=("Cost Explorer reported matching service spend in the selected scan window."),
                precheck_mode="matched_billing_spend",
                billing_match_required_to_run=(rule.require_billing_match_to_run if rule else True),
            )
        billing_match_required = rule.require_billing_match_to_run if rule else True
        if not billing_match_required:
            return ServiceUsagePrecheckDecision(
                scanner_id=scanner_id,
                should_run=True,
                configured_service_patterns=patterns,
                reason=(
                    rule.no_spend_run_reason if rule else ("Cost Explorer showed no matching service spend, but this scanner does not require a billing match.")
                ),
                precheck_mode="metadata_scan_without_billing_match",
                billing_match_required_to_run=False,
            )
        return ServiceUsagePrecheckDecision(
            scanner_id=scanner_id,
            should_run=False,
            configured_service_patterns=patterns,
            reason=("Skipped by service-usage precheck because Cost Explorer did not show matching service spend in the selected scan window."),
            precheck_mode="skipped_without_billing_match",
            billing_match_required_to_run=True,
        )

    def build_summary(self) -> dict[str, object]:
        """Return safe metadata about configured service-usage prechecks."""
        return {
            "enabled": self.enabled,
            "force_run": self.force_run,
            "configured_scanner_count": len(SERVICE_USAGE_PRECHECK_SCANNERS),
            "configured_scanner_ids": sorted(SERVICE_USAGE_PRECHECK_SCANNERS),
            "contains_client_result_data": False,
        }

    def _find_matching_current_spend_services(
        self,
        patterns: tuple[str, ...],
        deltas: tuple[ServiceSpendDelta, ...],
    ) -> tuple[str, ...]:
        matches: list[str] = []
        for delta in deltas:
            if delta.current_cost <= Decimal(0):
                continue
            if self._matches_any_pattern(delta.service_name, patterns):
                matches.append(delta.service_name)
        return tuple(sorted(dict.fromkeys(matches)))

    def _matches_any_pattern(self, service_name: str, patterns: tuple[str, ...]) -> bool:
        normalized_service = self._normalize(service_name)
        for pattern in patterns:
            normalized_pattern = self._normalize(pattern)
            if normalized_pattern == normalized_service or normalized_pattern in normalized_service or normalized_service in normalized_pattern:
                return True
        return False

    def _normalize(self, value: str) -> str:
        return " ".join(value.casefold().replace("-", " ").split())
