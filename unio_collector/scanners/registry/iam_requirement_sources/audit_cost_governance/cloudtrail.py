from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "CloudTrail trail",
    "Event selector",
    "CloudTrail Lake event data store",
)

CLOUDTRAIL_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "cloudtrail-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "CloudTrail cost governance review requires ec2:DescribeRegions to collect read-only CloudTrail trail, "
                "Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:DescribeTrails",
                "required",
                "CloudTrail cost governance review requires cloudtrail:DescribeTrails to collect read-only "
                "CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:DescribeTrails is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetTrailStatus",
                "required",
                "CloudTrail cost governance review requires cloudtrail:GetTrailStatus to collect read-only "
                "CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetTrailStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetEventSelectors",
                "required",
                "CloudTrail cost governance review requires cloudtrail:GetEventSelectors to collect read-only "
                "CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetEventSelectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetInsightSelectors",
                "required",
                "CloudTrail cost governance review requires cloudtrail:GetInsightSelectors to collect "
                "read-only CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetInsightSelectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:ListEventDataStores",
                "required",
                "CloudTrail cost governance review requires cloudtrail:ListEventDataStores to collect "
                "read-only CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:ListEventDataStores is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetEventDataStore",
                "required",
                "CloudTrail cost governance review requires cloudtrail:GetEventDataStore to collect read-only "
                "CloudTrail trail, Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetEventDataStore is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "CloudTrail cost governance review requires ce:GetCostAndUsage to collect read-only CloudTrail trail, "
                "Event selector, CloudTrail Lake event data store evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
