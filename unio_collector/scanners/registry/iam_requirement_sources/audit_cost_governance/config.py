from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "Configuration recorder",
    "Config rule",
    "Conformance pack",
)

CONFIG_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "config-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "AWS Config cost governance review requires ec2:DescribeRegions to collect read-only Configuration "
                "recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigurationRecorders",
                "required",
                "AWS Config cost governance review requires config:DescribeConfigurationRecorders to "
                "collect read-only Configuration recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigurationRecorders is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigurationRecorderStatus",
                "required",
                "AWS Config cost governance review requires "
                "config:DescribeConfigurationRecorderStatus to collect read-only Configuration "
                "recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigurationRecorderStatus is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeDeliveryChannels",
                "required",
                "AWS Config cost governance review requires config:DescribeDeliveryChannels to collect "
                "read-only Configuration recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeDeliveryChannels is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigRules",
                "required",
                "AWS Config cost governance review requires config:DescribeConfigRules to collect read-only "
                "Configuration recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigRules is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConformancePacks",
                "required",
                "AWS Config cost governance review requires config:DescribeConformancePacks to collect "
                "read-only Configuration recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConformancePacks is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "AWS Config cost governance review requires ce:GetCostAndUsage to collect read-only Configuration "
                "recorder, Config rule, Conformance pack evidence.",
                chargeable=False,
                evidence_categories=CONFIG_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
