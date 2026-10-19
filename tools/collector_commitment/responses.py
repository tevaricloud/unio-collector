"""Reviewed finite local SDK responses; no AWS access or customer material."""

RESPONSES = {
    "describe_reserved_instances": {
        "ReservedInstances": [
            {
                "CurrencyCode": "USD",
                "InstanceTenancy": "default",
                "OfferingClass": "standard",
                "OfferingType": "Partial Upfront",
                "RecurringCharges": [{"Amount": 0.25, "Frequency": "Hourly"}],
                "Scope": "Region",
                "ReservedInstancesId": "ri-offline-001",
                "InstanceType": "m6i.large",
                "Start": "2025-09-01T00:00:00Z",
                "End": "2026-09-01T00:00:00Z",
                "Duration": 31536000,
                "FixedPrice": 100.5,
                "InstanceCount": 2,
                "ProductDescription": "Linux/UNIX",
                "State": "active",
            }
        ],
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-ri-populated", "RetryAttempts": 0},
    },
    "describe_savings_plans": {
        "savingsPlans": [
            {
                "savingsPlanId": "sp-offline-001",
                "savingsPlanArn": "arn:aws:savingsplans::123456789012:savingsplan/sp-offline-001",
                "description": "offline synthetic plan",
                "start": "2025-09-01T00:00:00Z",
                "end": "2026-09-01T00:00:00Z",
                "state": "active",
                "region": "eu-west-1",
                "ec2InstanceFamily": "m6i",
                "savingsPlanType": "EC2Instance",
                "paymentOption": "No Upfront",
                "productTypes": ["EC2"],
                "currency": "USD",
                "commitment": "1.00",
                "upfrontPaymentAmount": "0",
                "recurringPaymentAmount": "1.00",
                "termDurationInSeconds": 31536000,
                "tags": {},
            }
        ],
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-sp-inventory-populated", "RetryAttempts": 0},
    },
    "get_reservation_utilization": {
        "UtilizationsByTime": [],
        "Total": {
            "UtilizationPercentage": "75",
            "UtilizationPercentageInUnits": "80",
            "PurchasedHours": "744",
            "PurchasedUnits": "1488",
            "UnusedHours": "186",
            "UnusedUnits": "297.6",
            "TotalAmortizedFee": "100",
            "RICostForUnusedHours": "20",
            "RealizedSavings": "35",
        },
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-ri-util-populated", "RetryAttempts": 0},
    },
    "get_reservation_coverage": {
        "CoveragesByTime": [],
        "Total": {
            "CoverageHours": {"OnDemandHours": "100", "ReservedHours": "400", "TotalRunningHours": "500", "CoverageHoursPercentage": "80"},
            "CoverageNormalizedUnits": {
                "OnDemandNormalizedUnits": "200",
                "ReservedNormalizedUnits": "800",
                "TotalRunningNormalizedUnits": "1000",
                "CoverageNormalizedUnitsPercentage": "80",
            },
            "CoverageCost": {"OnDemandCost": "25"},
        },
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-ri-coverage-populated", "RetryAttempts": 0},
    },
    "get_savings_plans_utilization": {
        "SavingsPlansUtilizationsByTime": [],
        "Total": {
            "Utilization": {"TotalCommitment": "100", "UsedCommitment": "85", "UnusedCommitment": "15", "UtilizationPercentage": "85"},
            "Savings": {"NetSavings": "20", "OnDemandCostEquivalent": "120"},
            "AmortizedCommitment": {"AmortizedRecurringCommitment": "100", "AmortizedUpfrontCommitment": "0", "TotalAmortizedCommitment": "100"},
        },
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-sp-util-populated", "RetryAttempts": 0},
    },
    "get_savings_plans_coverage": {
        "SavingsPlansCoverages": [
            {
                "Attributes": {"region": "eu-west-1", "instanceFamily": "m6i"},
                "Coverage": {"SpendCoveredBySavingsPlans": "80", "OnDemandCost": "20", "TotalCost": "100", "CoveragePercentage": "80"},
                "TimePeriod": {"Start": "2026-01-01", "End": "2026-02-01"},
            }
        ],
        "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "offline-sp-coverage-populated", "RetryAttempts": 0},
    },
}
