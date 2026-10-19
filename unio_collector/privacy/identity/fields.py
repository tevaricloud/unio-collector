"""Explicit emitted DTO paths and finite IAM/security provider vocabularies."""

from unio_collector.privacy.identity.policy import POLICY_FIELDS
from unio_collector.privacy.s3.fields import fields

VOCABULARIES = {
    "effect": {"Allow", "Deny"},
    "policy_version": {"2008-10-17", "2012-10-17"},
    "password_status": {"legacy", "complete", "absent", "unavailable"},
    "key_status": {"Active", "Inactive", "Expired"},
    "principal_kind": {"user", "group", "role"},
    "policy_source": {"inline", "managed"},
    "analyzer_type": {
        "ACCOUNT",
        "ORGANIZATION",
        "ACCOUNT_UNUSED_ACCESS",
        "ORGANIZATION_UNUSED_ACCESS",
        "ACCOUNT_INTERNAL_ACCESS",
        "ORGANIZATION_INTERNAL_ACCESS",
        "UNKNOWN",
    },
    "analyzer_status": {"ACTIVE", "CREATING", "DISABLED", "FAILED"},
    "finding_status": {"ACTIVE", "NEW"},
    "finding_type": {"ExternalAccess", "UnusedIAMRole", "UnusedIAMUserAccessKey", "UnusedIAMUserPassword", "UnusedPermission", "InternalAccess", "UNKNOWN"},
    "instance_status": {"CREATE_IN_PROGRESS", "CREATE_FAILED", "DELETE_IN_PROGRESS", "ACTIVE"},
    "security_service": {"CloudTrail", "AWS Config", "GuardDuty", "Security Hub"},
    "inventory_status": {"complete", "partial", "capped", "unavailable"},
}
ROOT = {"": ("object", "safe_metadata", False), **fields("warnings", "array"), **fields("warnings[]", "string", "free_text")}
ACCOUNT = {
    **POLICY_FIELDS,
    **ROOT,
    **fields("account_id", "string", "aws_account_id"),
    **fields("collection_evidence_version", "count", "summary_count"),
    **fields("account_summary", "object"),
    **fields("password_policy", "object", nullable=True),
    **fields("password_policy_status", "password_status"),
    **fields("users policy_grants", "array"),
    **fields("users[] policy_grants[]", "object"),
    **fields("users[].user_name policy_grants[].principal_name policy_grants[].policy_name", "string", "resource_name"),
    **fields("users[].user_id", "string", "resource_id", nullable=True),
    **fields("users[].arn policy_grants[].principal_arn policy_grants[].policy_arn", "string", "arn", nullable=True),
    **fields("users[].has_console_profile", "boolean", nullable=True),
    **fields("users[].mfa_device_count", "count", "summary_count", nullable=True),
    **fields(
        "users[].login_profile_created_at users[].password_last_used_at users[].access_keys[].created_at users[].access_keys[].last_used_at",
        "timestamp",
        "timestamp",
        nullable=True,
    ),
    **fields("users[].access_keys", "array"),
    **fields("users[].access_keys[]", "object"),
    **fields("users[].access_keys[].access_key_id", "string", "resource_id"),
    **fields("users[].access_keys[].status", "key_status"),
    **fields("users[].access_keys[].last_used_service", "string", "free_text", nullable=True),
    **fields("users[].access_keys[].last_used_region", "string", "region", nullable=True),
    **fields("users[].access_keys[].last_used_available", "boolean"),
    **fields("policy_grants[].principal_type", "principal_kind"),
    **fields("policy_grants[].policy_source", "policy_source"),
    **fields("policy_grants[].policy_document", "object", nullable=True),
}
SUMMARY_KEYS = [
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
    "AccountPasswordPresent",
    "AssumeRolePolicySizeQuota",
    "InstanceProfiles",
    "InstanceProfilesQuota",
    "Providers",
    "RolePolicySizeQuota",
    "Roles",
    "RolesQuota",
]
ACCOUNT.update(fields(" ".join("account_summary." + key for key in SUMMARY_KEYS), "count", "summary_count"))
ACCOUNT.update(fields("password_policy.MinimumPasswordLength password_policy.MaxPasswordAge password_policy.PasswordReusePrevention", "count", "summary_count"))
ACCOUNT.update(
    fields(
        " ".join(
            "password_policy." + key
            for key in [
                "RequireSymbols",
                "RequireNumbers",
                "RequireUppercaseCharacters",
                "RequireLowercaseCharacters",
                "AllowUsersToChangePassword",
                "ExpirePasswords",
                "HardExpiry",
            ]
        ),
        "boolean",
    )
)
ANALYZER = {
    **ROOT,
    **fields("analyzers findings regions", "array"),
    **fields("analyzers[] findings[]", "object"),
    **fields("regions[] analyzers[].region findings[].region", "string", "region"),
    **fields("collection_evidence_version", "count", "summary_count"),
    **fields("analyzer_inventory_status", "object"),
    **fields("analyzers[].analyzer_name findings[].analyzer_name", "string", "resource_name"),
    **fields("analyzers[].analyzer_arn findings[].analyzer_arn", "string", "arn"),
    **fields("analyzers[].analyzer_type findings[].analyzer_type", "analyzer_type"),
    **fields("analyzers[].status", "analyzer_status", nullable=True),
    **fields("findings[].finding_id", "string", "resource_id"),
    **fields("findings[].finding_type", "finding_type"),
    **fields("findings[].status", "finding_status"),
    **fields("findings[].resource", "string", "arn_or_name", nullable=True),
    **fields("findings[].resource_type findings[].principal", "string", "free_text", nullable=True),
    **fields("findings[].created_at findings[].updated_at", "timestamp", "timestamp", nullable=True),
}
CENTER = {
    **ROOT,
    **fields("account_id", "string", "aws_account_id"),
    **fields("instances", "array"),
    **fields("instances[]", "object"),
    **fields("instances[].instance_arn instances[].permission_sets[].instance_arn instances[].permission_sets[].permission_set_arn", "string", "arn"),
    **fields("instances[].identity_store_id instances[].permission_sets[].identity_store_id", "string", "resource_id", nullable=True),
    **fields("instances[].owner_account_id", "string", "aws_account_id", nullable=True),
    **fields("instances[].name", "string", "resource_name", nullable=True),
    **fields("instances[].status", "instance_status", nullable=True),
    **fields("instances[].created_at", "timestamp", "timestamp", nullable=True),
    **fields("instances[].permission_sets", "array"),
    **fields("instances[].permission_sets[]", "object"),
    **fields("instances[].permission_sets[].name", "string", "resource_name"),
    **fields(
        "instances[].permission_sets[].description instances[].permission_sets[].relay_state instances[].permission_sets[].session_duration",
        "string",
        "free_text",
        nullable=True,
    ),
    **fields("instances[].permission_sets[].managed_policy_arns instances[].permission_sets[].customer_managed_policy_names", "array"),
    **fields("instances[].permission_sets[].managed_policy_arns[]", "string", "arn"),
    **fields("instances[].permission_sets[].customer_managed_policy_names[]", "string", "resource_name"),
}
COVERAGE = {
    **ROOT,
    **fields("records regions", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].service_name", "security_service"),
    **fields("records[].enabled", "boolean", nullable=True),
    **fields("records[].detail", "string", "free_text"),
    **fields("records[].metadata", "object"),
    **fields(
        " ".join(
            "records[].metadata." + key
            for key in [
                "visible_trail_count",
                "multi_region_trail_count",
                "organization_trail_count",
                "recorder_count",
                "aggregator_count",
                "conformance_pack_count",
            ]
        ),
        "count",
        "summary_count",
    ),
    **fields("records[].metadata.recording", "boolean", nullable=True),
    **fields("records[].metadata.aggregator_names records[].metadata.conformance_pack_names", "array"),
    **fields("records[].metadata.aggregator_names[] records[].metadata.conformance_pack_names[]", "string", "resource_name"),
}
SCANNERS = {
    "iam-account-security-review": ("iam.account_security.evidence", "IamAccountSecurityEvidence", ACCOUNT),
    "iam-access-analyzer-evidence-review": ("access_analyzer.evidence", "AccessAnalyzerEvidence", ANALYZER),
    "iam-identity-center-visibility-review": ("identity_center.evidence", "IdentityCenterEvidence", CENTER),
    "aws-security-service-coverage-review": ("security_governance.service.coverage.evidence", "SecurityServiceCoverageEvidence", COVERAGE),
}
