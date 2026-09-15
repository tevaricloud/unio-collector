from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

ACCOUNT_COST_RISK_SIGNAL_REVIEW_EVIDENCE = (
    "Cost signal",
    "Governance signal",
)

BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE = (
    "Billing monitor",
    "Budget",
)

COMMITMENT_AND_PRICING_REVIEW_EVIDENCE = (
    "Savings Plan",
    "Reserved Instance",
)

COST_EXPLORER_SERVICE_DELTA_EVIDENCE = ("AWS service spend",)

COST_SPIKE_ANALYSIS_EVIDENCE = ("Daily spend",)

FREE_TIER_USAGE_REVIEW_EVIDENCE = (
    "Free Tier account plan",
    "Free Tier usage allowance",
)

ROOT_ACCOUNT_RECOVERY_ADVISORY_EVIDENCE = ("Governance advisory",)

COST_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "account-cost-risk-signal-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Account cost-risk signal review requires ce:GetCostAndUsage to collect read-only Cost signal, Governance signal evidence.",
                chargeable=False,
                evidence_categories=ACCOUNT_COST_RISK_SIGNAL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:DescribeTrails",
                "required",
                "Account cost-risk signal review requires cloudtrail:DescribeTrails to collect read-only Cost signal, Governance signal evidence.",
                chargeable=False,
                evidence_categories=ACCOUNT_COST_RISK_SIGNAL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:DescribeTrails is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetTrailStatus",
                "required",
                "Account cost-risk signal review requires cloudtrail:GetTrailStatus to collect read-only Cost signal, Governance signal evidence.",
                chargeable=False,
                evidence_categories=ACCOUNT_COST_RISK_SIGNAL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetTrailStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetAccountSummary",
                "required",
                "Account cost-risk signal review requires iam:GetAccountSummary to collect read-only Cost signal, Governance signal evidence.",
                chargeable=False,
                evidence_categories=ACCOUNT_COST_RISK_SIGNAL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetAccountSummary is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "billing-alerts-and-budgets-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "budgets:DescribeBudgets",
                "required",
                "Billing monitoring and budgets review requires budgets:DescribeBudgets to collect read-only Billing monitor, Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="budgets:DescribeBudgets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "budgets:DescribeNotificationsForBudget",
                "required",
                "Billing monitoring and budgets review requires budgets:DescribeNotificationsForBudget to collect read-only Billing monitor, Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="budgets:DescribeNotificationsForBudget is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "budgets:DescribeSubscribersForNotification",
                "required",
                "Billing monitoring and budgets review requires "
                "budgets:DescribeSubscribersForNotification to collect read-only Billing monitor, "
                "Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="budgets:DescribeSubscribersForNotification is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetAnomalyMonitors",
                "required",
                "Billing monitoring and budgets review requires ce:GetAnomalyMonitors to collect read-only Billing monitor, Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetAnomalyMonitors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetAnomalySubscriptions",
                "required",
                "Billing monitoring and budgets review requires ce:GetAnomalySubscriptions to collect read-only Billing monitor, Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetAnomalySubscriptions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:DescribeAlarms",
                "required",
                "Billing monitoring and budgets review requires cloudwatch:DescribeAlarms to collect read-only Billing monitor, Budget evidence.",
                chargeable=False,
                evidence_categories=BILLING_ALERTS_AND_BUDGETS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:DescribeAlarms is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "commitment-and-pricing-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeReservedInstances",
                "required",
                "Commitment and pricing review requires ec2:DescribeReservedInstances to collect read-only Reserved Instance inventory evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeReservedInstances does not support resource-level IAM constraints for inventory enumeration.",
                conditional_on=None,
            ),
            Req(
                "savingsplans:DescribeSavingsPlans",
                "required",
                "Commitment and pricing review requires savingsplans:DescribeSavingsPlans to collect read-only Savings Plan inventory evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="Savings Plans inventory enumeration is rendered with Resource='*'.",
                conditional_on=None,
            ),
            Req(
                "ce:GetSavingsPlansUtilization",
                "required",
                "Commitment and pricing review requires ce:GetSavingsPlansUtilization to collect read-only Savings Plan, Reserved Instance evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetSavingsPlansUtilization is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetSavingsPlansCoverage",
                "required",
                "Commitment and pricing review requires ce:GetSavingsPlansCoverage to collect read-only Savings Plan coverage evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="Cost Explorer coverage APIs require Resource='*'.",
                conditional_on=None,
            ),
            Req(
                "ce:GetReservationUtilization",
                "required",
                "Commitment and pricing review requires ce:GetReservationUtilization to collect read-only Savings Plan, Reserved Instance evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetReservationUtilization is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetReservationCoverage",
                "required",
                "Commitment and pricing review requires ce:GetReservationCoverage to collect read-only Reserved Instance coverage evidence.",
                chargeable=False,
                evidence_categories=COMMITMENT_AND_PRICING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="Cost Explorer coverage APIs require Resource='*'.",
                conditional_on=None,
            ),
        ),
    ),
    "cost-explorer-service-delta": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Cost Explorer service delta requires ce:GetCostAndUsage to collect read-only AWS service spend evidence.",
                chargeable=False,
                evidence_categories=COST_EXPLORER_SERVICE_DELTA_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "cost-spike-analysis": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Cost spike analysis requires ce:GetCostAndUsage to collect read-only Daily spend evidence.",
                chargeable=False,
                evidence_categories=COST_SPIKE_ANALYSIS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "free-tier-usage-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "freetier:GetAccountPlanState",
                "required",
                "Free Tier usage review requires freetier:GetAccountPlanState to collect read-only Free Tier account plan, Free Tier usage allowance evidence.",
                chargeable=False,
                evidence_categories=FREE_TIER_USAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="freetier:GetAccountPlanState is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "freetier:GetFreeTierUsage",
                "required",
                "Free Tier usage review requires freetier:GetFreeTierUsage to collect read-only Free Tier account plan, Free Tier usage allowance evidence.",
                chargeable=False,
                evidence_categories=FREE_TIER_USAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="freetier:GetFreeTierUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "root-account-recovery-advisory": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "sts:GetCallerIdentity",
                "required",
                "Root account recovery advisory requires sts:GetCallerIdentity to collect read-only Governance advisory evidence.",
                chargeable=False,
                evidence_categories=ROOT_ACCOUNT_RECOVERY_ADVISORY_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sts:GetCallerIdentity is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
