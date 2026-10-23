"""Finite producer controls; provider attributes remain protected strings."""

from __future__ import annotations

from unio_collector.privacy.network.facts import enum_values

VOCABULARIES = {
    "schema": frozenset({"2026-08"}),
    "pricing": frozenset({"aws-native-cost-explorer"}),
    "provider": frozenset({"aws"}),
    "service": frozenset({"ec2_reserved_instance", "savings_plans"}),
    "namespace": frozenset({"ec2_reserved_instances_id", "savings_plan_id"}),
    "nature": frozenset({"aws_observed", "aws_calculated", "unio_calculated", "unio_annualized", "unknown"}),
    "outcome": frozenset({"success", "success_empty", "partial", "malformed", "unavailable", "account_scope_unproven"}),
    "operation": frozenset(
        {
            "ec2:DescribeReservedInstances",
            "savingsplans:DescribeSavingsPlans",
            "ce:GetReservationUtilization",
            "ce:GetReservationCoverage",
            "ce:GetSavingsPlansUtilization",
            "ce:GetSavingsPlansCoverage",
        }
    ),
    "metric": frozenset(
        {
            "utilization_percentage",
            "purchased_hours",
            "purchased_units",
            "unused_hours",
            "unused_units",
            "effective_cost",
            "estimated_waste",
            "estimated_avoided_ondemand_spend",
            "ondemand_equivalent",
            "coverage_percentage",
            "uncovered_eligible_usage",
            "covered_usage",
            "total_eligible_usage",
            "uncovered_ondemand_cost",
            "total_commitment",
            "used_commitment",
            "unused_commitment",
            "spend_covered",
            "total_eligible_cost",
        }
    ),
    "unit": frozenset({"percent", "hours", "normalized_units", "currency"}),
    "source_field": frozenset(
        {
            "UtilizationPercentageInUnits",
            "UtilizationPercentage",
            "PurchasedHours",
            "PurchasedUnits",
            "UnusedHours",
            "UnusedUnits",
            "TotalAmortizedFee",
            "RICostForUnusedHours",
            "RealizedSavings",
            "OnDemandCostOfRIHoursUsed",
            "CoveragePercentage",
            "OnDemand",
            "Reserved",
            "Total",
            "OnDemandCost",
            "TotalCommitment",
            "UsedCommitment",
            "UnusedCommitment",
            "TotalAmortizedCommitment",
            "NetSavings",
            "OnDemandCostEquivalent",
            "SpendCoveredBySavingsPlans",
            "TotalCost",
        }
    ),
}


INSTANCE_TYPES = enum_values("InstanceType")
CURRENCIES = frozenset({"USD", "CNY", "EUR"})
PUBLIC_ROLES = {
    "instance_type": INSTANCE_TYPES,
    "instance_family": frozenset(value.split(".", maxsplit=1)[0] for value in INSTANCE_TYPES),
    "platform": enum_values("RIProductDescription"),
    "payment_option": enum_values("OfferingTypeValues"),
    "scope": frozenset({"Region", "Availability Zone", "global"}),
    "commitment_class": frozenset({"standard", "convertible"}),
    "tenancy": frozenset({"default", "dedicated", "host"}),
    "lifecycle_state": frozenset({"payment-pending", "active", "payment-failed", "retired", "queued", "queued-deleted", "pending-return", "returned"}),
    "source": VOCABULARIES["operation"],
    "commitment_type": frozenset({"reserved_instance", "savings_plan", "EC2Instance", "Compute", "SageMaker"}),
    "capacity_unit": frozenset({"instances", "currency_per_hour"}),
    "term_label": frozenset({"one_year", "three_year"}),
    "recurring_unit": frozenset({"hour"}),
}
DIMENSION_KEYS = frozenset(
    {
        "_grouping",
        "region",
        "REGION",
        "availabilityZone",
        "AZ",
        "instanceFamily",
        "instanceType",
        "INSTANCE_TYPE",
        "platform",
        "PLATFORM",
        "tenancy",
        "TENANCY",
        "service",
        "SERVICE",
    }
)
GROUPINGS = frozenset({"region_instance_family", "service"})
