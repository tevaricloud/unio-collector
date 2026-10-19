"""Closed privacy policy for actual account-cost-risk collection evidence."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

IAM_COUNTERS = (
    "Users",
    "UsersQuota",
    "Groups",
    "GroupsQuota",
    "ServerCertificates",
    "ServerCertificatesQuota",
    "UserPolicySizeQuota",
    "GroupPolicySizeQuota",
    "GroupsPerUserQuota",
    "SigningCertificatesPerUserQuota",
    "AccessKeysPerUserQuota",
    "MFADevices",
    "MFADevicesInUse",
    "AccountMFAEnabled",
    "AccountAccessKeysPresent",
    "AccountPasswordPresent",
    "AccountSigningCertificatesPresent",
    "AttachedPoliciesPerGroupQuota",
    "AttachedPoliciesPerRoleQuota",
    "AttachedPoliciesPerUserQuota",
    "Policies",
    "PoliciesQuota",
    "PolicySizeQuota",
    "PolicyVersionsInUse",
    "PolicyVersionsInUseQuota",
    "VersionsPerPolicyQuota",
    "GlobalEndpointTokenVersion",
    "AssumeRolePolicySizeQuota",
    "InstanceProfiles",
    "InstanceProfilesQuota",
    "Providers",
    "RolePolicySizeQuota",
    "Roles",
    "RolesQuota",
)
TRAIL_FIELDS = {
    "Name": ("string", "resource_name", False),
    "S3BucketName": ("string", "bucket_name", False),
    "S3KeyPrefix": ("string", "resource_name", False),
    "SnsTopicName": ("string", "resource_name", False),
    "SnsTopicARN": ("string", "arn", False),
    "HomeRegion": ("string", "region", False),
    "TrailARN": ("string", "arn", False),
    "CloudWatchLogsLogGroupArn": ("string", "arn", False),
    "CloudWatchLogsRoleArn": ("string", "arn", False),
    "KmsKeyId": ("string", "resource_id", False),
    **dict.fromkeys(
        (
            "IncludeGlobalServiceEvents",
            "IsMultiRegionTrail",
            "LogFileValidationEnabled",
            "HasCustomEventSelectors",
            "HasInsightSelectors",
            "IsOrganizationTrail",
            "RecursiveLogging",
        ),
        ("boolean", "safe_metadata", False),
    ),
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "daily_costs": ("array", "safe_metadata", False),
    "daily_costs[]": ("object", "safe_metadata", False),
    "daily_costs[].date": ("string", "timestamp", False),
    "daily_costs[].service_name": ("string", "free_text", False),
    "daily_costs[].region": ("string", "region", False),
    "daily_costs[].usage_type": ("string", "free_text", True),
    "daily_costs[].cost": ("money", "cost", False),
    "daily_costs[].currency": ("string", "cost", False),
    "account_risk": ("object", "safe_metadata", True),
    "account_risk.account_id": ("string", "aws_account_id", False),
    **{
        f"account_risk.{key}": ("boolean", "safe_metadata", False)
        for key in (
            "cloudtrail_available",
            "iam_summary_available",
            "trail_statuses_complete",
        )
    },
    "account_risk.trail_status_omitted_count": ("count", "safe_metadata", False),
    "account_risk.collection_errors": ("array", "removed_diagnostic", False),
    "account_risk.collection_errors[]": ("string", "removed_diagnostic", False),
    "account_risk.iam_summary": ("object", "safe_metadata", False),
    **{f"account_risk.iam_summary.{key}": ("count", "safe_metadata", False) for key in IAM_COUNTERS},
    "account_risk.trails": ("array", "safe_metadata", False),
    "account_risk.trails[]": ("object", "safe_metadata", False),
    **{f"account_risk.trails[].{key}": spec for key, spec in TRAIL_FIELDS.items()},
    "account_risk.trail_statuses": ("array", "safe_metadata", False),
    "account_risk.trail_statuses[]": ("object", "safe_metadata", False),
    "account_risk.trail_statuses[].trail": ("string", "arn_or_name", False),
    "account_risk.trail_statuses[].is_logging": ("boolean", "safe_metadata", True),
    "account_risk.trail_statuses[].latest_delivery_error": ("string", "removed_diagnostic", True),
}


class AccountRiskPrivacyContract(ClosedProducerContract):
    """Select the exact legacy account-risk identity; unknown schemas stay closed."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Admit only the existing producer, without registering a new schema."""
        if record.get("scanner_id") != "account-cost-risk-signal-review":
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.account_risk.cost.evidence", "AccountCostRiskEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Account-risk privacy contract requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()
