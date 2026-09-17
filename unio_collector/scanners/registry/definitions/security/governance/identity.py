from __future__ import annotations  # noqa: D100

from unio_collector.scanners.scanner.definition import ScannerDefinition

SECURITY_GOVERNANCE_IDENTITY_SCANNERS: dict[str, ScannerDefinition] = {
    "iam-account-security-review": ScannerDefinition(
        scanner_id="iam-account-security-review",
        display_name="IAM account security review",
        description=(
            "Reviews IAM account summary, root MFA status, account password "
            "policy, IAM users with console profiles, visible MFA devices, and "
            "IAM access key age, last-used metadata, direct AdministratorAccess "
            "attachments, and optional inline wildcard administrator policies "
            "as reusable security governance evidence."
        ),
        aws_services=("AWS IAM",),
        resource_types=(
            "AWS account",
            "IAM password policy",
            "IAM user",
            "IAM access key",
            "IAM group",
            "IAM role",
            "IAM policy",
        ),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=(
            "iam:GetAccountSummary",
            "iam:GetAccountPasswordPolicy",
            "iam:ListUsers",
            "iam:GetLoginProfile",
            "iam:ListMFADevices",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed",
            "iam:ListEntitiesForPolicy",
            "iam:ListUserPolicies",
            "iam:GetUserPolicy",
            "iam:ListGroups",
            "iam:ListGroupPolicies",
            "iam:GetGroupPolicy",
            "iam:ListRoles",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "iam:GetAccountSummary",
            "iam:GetAccountPasswordPolicy",
            "iam:ListUsers",
            "iam:GetLoginProfile",
            "iam:ListMFADevices",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed",
            "iam:ListEntitiesForPolicy",
            "iam:ListUserPolicies",
            "iam:GetUserPolicy",
            "iam:ListGroups",
            "iam:ListGroupPolicies",
            "iam:GetGroupPolicy",
            "iam:ListRoles",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
        ),
        risk_level="medium",
        output_finding_types=(
            "iam_root_mfa_gap",
            "iam_password_policy_gap",
            "iam_user_mfa_gap",
            "iam_access_key_age_review",
            "iam_access_key_unused_review",
            "iam_console_password_unused_review",
            "iam_administrator_access_policy_review",
            "iam_inline_wildcard_admin_policy_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not inspect identity-provider users, SSO assignments, or external directory policies.",
            "IAM user MFA evidence is limited to visible IAM users and does not prove MFA enforcement for federated identities.",
            "Access key age and last-used metadata are review signals, not proof that a key is unused or unsafe.",
            (
                "Policy review detects direct AWS managed AdministratorAccess "
                "attachments by default. Inline Action=* Resource=* policy expansion "
                "requires scanners.iam-account-security-review.policy_detail_mode: "
                "full. It does not simulate effective permissions or expand managed "
                "customer policy versions."
            ),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized IAM account security evidence with account identity carried in evidence."),
    ),
    "iam-identity-center-visibility-review": ScannerDefinition(
        scanner_id="iam-identity-center-visibility-review",
        display_name="IAM Identity Center visibility review",
        description=(
            "Reviews IAM Identity Center instance and permission set visibility, "
            "including AdministratorAccess permission set signals, as reusable "
            "identity-governance evidence."
        ),
        aws_services=("AWS IAM Identity Center",),
        resource_types=(
            "IAM Identity Center instance",
            "IAM Identity Center permission set",
        ),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=(
            "sso:ListInstances",
            "sso:ListPermissionSets",
            "sso:DescribePermissionSet",
            "sso:ListManagedPoliciesInPermissionSet",
            "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "sso-admin:ListInstances",
            "sso-admin:ListPermissionSets",
            "sso-admin:DescribePermissionSet",
            "sso-admin:ListManagedPoliciesInPermissionSet",
            "sso-admin:ListCustomerManagedPolicyReferencesInPermissionSet",
        ),
        risk_level="medium",
        output_finding_types=(
            "iam_identity_center_visibility_review",
            "iam_identity_center_permission_set_visibility_review",
            "iam_identity_center_administrator_permission_set_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not inspect external IdP password policy, user lifecycle, group membership intent, or SCIM provisioning controls.",
            "Assignments may be managed from a delegated administration account; absence in this account is not proof that Identity Center is absent.",
            "AdministratorAccess permission sets can be intentional break-glass or platform-admin controls and require owner validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized IAM Identity Center evidence with "
            "account identity carried in evidence; summary side-channel writes "
            "are optional during strict replay."
        ),
    ),
    "iam-access-analyzer-evidence-review": ScannerDefinition(
        scanner_id="iam-access-analyzer-evidence-review",
        display_name="IAM Access Analyzer evidence review",
        description=(
            "Reviews IAM Access Analyzer analyzer coverage and active external "
            "or unused-access findings as reusable identity and resource-policy "
            "governance evidence."
        ),
        aws_services=("AWS IAM Access Analyzer",),
        resource_types=(
            "IAM Access Analyzer regional coverage",
            "IAM Access Analyzer finding",
            "AWS resource policy",
            "IAM access path",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "access-analyzer:ListAnalyzers",
            "access-analyzer:ListFindingsV2",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "accessanalyzer:ListAnalyzers",
            "accessanalyzer:ListFindingsV2",
        ),
        risk_level="high",
        output_finding_types=(
            "iam_access_analyzer_coverage_gap",
            "iam_access_analyzer_external_access_finding",
            "iam_access_analyzer_unused_access_finding",
        ),
        maturity="experimental",
        limitations=(
            "Does not decide whether external access is approved; policy owner validation and archive reasons remain required.",
            "Unused-access findings depend on Access Analyzer feature coverage and may not cover every identity-provider or workload permission.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized IAM Access Analyzer evidence and uses scanner metadata for deterministic finding ownership."),
    ),
}

__all__ = ["SECURITY_GOVERNANCE_IDENTITY_SCANNERS"]
