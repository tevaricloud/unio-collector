from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

IAM_ACCESS_ANALYZER_EVIDENCE_REVIEW_EVIDENCE = (
    "IAM Access Analyzer regional coverage",
    "IAM Access Analyzer finding",
    "AWS resource policy",
    "IAM access path",
)

IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE = (
    "AWS account",
    "IAM password policy",
    "IAM user",
    "IAM access key",
    "IAM group",
    "IAM role",
    "IAM policy",
)

IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE = (
    "IAM Identity Center instance",
    "IAM Identity Center permission set",
)

KMS_KEY_POSTURE_REVIEW_EVIDENCE = ("KMS key",)

SECURITY_IDENTITY_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "iam-access-analyzer-evidence-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "IAM Access Analyzer evidence review requires ec2:DescribeRegions to collect read-only IAM Access "
                "Analyzer regional coverage, IAM Access Analyzer finding, AWS resource policy, IAM access path evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCESS_ANALYZER_EVIDENCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "access-analyzer:ListAnalyzers",
                "required",
                "IAM Access Analyzer evidence review requires access-analyzer:ListAnalyzers to collect "
                "read-only IAM Access Analyzer regional coverage, IAM Access Analyzer finding, AWS resource "
                "policy, IAM access path evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCESS_ANALYZER_EVIDENCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="access-analyzer:ListAnalyzers is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "access-analyzer:ListFindingsV2",
                "required",
                "IAM Access Analyzer evidence review requires access-analyzer:ListFindingsV2 to collect "
                "read-only IAM Access Analyzer regional coverage, IAM Access Analyzer finding, AWS resource "
                "policy, IAM access path evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCESS_ANALYZER_EVIDENCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="access-analyzer:ListFindingsV2 is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "iam-account-security-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "iam:GetAccountSummary",
                "required",
                "IAM account security review requires iam:GetAccountSummary to collect read-only AWS account, IAM "
                "password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetAccountSummary is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetAccountPasswordPolicy",
                "required",
                "IAM account security review requires iam:GetAccountPasswordPolicy to collect read-only AWS "
                "account, IAM password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy "
                "evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetAccountPasswordPolicy is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListUsers",
                "required",
                "IAM account security review requires iam:ListUsers to collect read-only AWS account, IAM password policy, IAM "
                "user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListUsers is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetLoginProfile",
                "required",
                "IAM account security review requires iam:GetLoginProfile to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetLoginProfile is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListMFADevices",
                "required",
                "IAM account security review requires iam:ListMFADevices to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListMFADevices is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListAccessKeys",
                "required",
                "IAM account security review requires iam:ListAccessKeys to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListAccessKeys is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetAccessKeyLastUsed",
                "required",
                "IAM account security review requires iam:GetAccessKeyLastUsed to collect read-only AWS account, IAM "
                "password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetAccessKeyLastUsed is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListEntitiesForPolicy",
                "required",
                "IAM account security review requires iam:ListEntitiesForPolicy to collect read-only AWS account, "
                "IAM password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListEntitiesForPolicy is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListUserPolicies",
                "required",
                "IAM account security review requires iam:ListUserPolicies to collect read-only AWS account, IAM "
                "password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListUserPolicies is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetUserPolicy",
                "required",
                "IAM account security review requires iam:GetUserPolicy to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetUserPolicy is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListGroups",
                "required",
                "IAM account security review requires iam:ListGroups to collect read-only AWS account, IAM password policy, "
                "IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListGroupPolicies",
                "required",
                "IAM account security review requires iam:ListGroupPolicies to collect read-only AWS account, IAM "
                "password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListGroupPolicies is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetGroupPolicy",
                "required",
                "IAM account security review requires iam:GetGroupPolicy to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetGroupPolicy is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListRoles",
                "required",
                "IAM account security review requires iam:ListRoles to collect read-only AWS account, IAM password policy, IAM "
                "user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListRoles is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:ListRolePolicies",
                "required",
                "IAM account security review requires iam:ListRolePolicies to collect read-only AWS account, IAM "
                "password policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:ListRolePolicies is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "iam:GetRolePolicy",
                "required",
                "IAM account security review requires iam:GetRolePolicy to collect read-only AWS account, IAM password "
                "policy, IAM user, IAM access key, IAM group, IAM role, IAM policy evidence.",
                chargeable=False,
                evidence_categories=IAM_ACCOUNT_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="iam:GetRolePolicy is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "iam-identity-center-visibility-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "sso:ListInstances",
                "required",
                "IAM Identity Center visibility review requires sso:ListInstances to collect read-only IAM Identity Center "
                "instance, IAM Identity Center permission set evidence.",
                chargeable=False,
                evidence_categories=IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sso:ListInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sso:ListPermissionSets",
                "required",
                "IAM Identity Center visibility review requires sso:ListPermissionSets to collect read-only IAM "
                "Identity Center instance, IAM Identity Center permission set evidence.",
                chargeable=False,
                evidence_categories=IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sso:ListPermissionSets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sso:DescribePermissionSet",
                "required",
                "IAM Identity Center visibility review requires sso:DescribePermissionSet to collect read-only IAM "
                "Identity Center instance, IAM Identity Center permission set evidence.",
                chargeable=False,
                evidence_categories=IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sso:DescribePermissionSet is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sso:ListManagedPoliciesInPermissionSet",
                "required",
                "IAM Identity Center visibility review requires sso:ListManagedPoliciesInPermissionSet "
                "to collect read-only IAM Identity Center instance, IAM Identity Center permission set "
                "evidence.",
                chargeable=False,
                evidence_categories=IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sso:ListManagedPoliciesInPermissionSet is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
                "required",
                "IAM Identity Center visibility review requires "
                "sso:ListCustomerManagedPolicyReferencesInPermissionSet to collect "
                "read-only IAM Identity Center instance, IAM Identity Center "
                "permission set evidence.",
                chargeable=False,
                evidence_categories=IAM_IDENTITY_CENTER_VISIBILITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sso:ListCustomerManagedPolicyReferencesInPermissionSet is rendered with Resource='*' because the scanner IAM metadata "
                "does not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "kms-key-posture-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "KMS key posture review requires ec2:DescribeRegions to collect read-only KMS key evidence.",
                chargeable=False,
                evidence_categories=KMS_KEY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:ListKeys",
                "required",
                "KMS key posture review requires kms:ListKeys to collect read-only KMS key evidence.",
                chargeable=False,
                evidence_categories=KMS_KEY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:ListKeys is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:DescribeKey",
                "required",
                "KMS key posture review requires kms:DescribeKey to collect read-only KMS key evidence.",
                chargeable=False,
                evidence_categories=KMS_KEY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:DescribeKey is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:GetKeyRotationStatus",
                "required",
                "KMS key posture review requires kms:GetKeyRotationStatus to collect read-only KMS key evidence.",
                chargeable=False,
                evidence_categories=KMS_KEY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:GetKeyRotationStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
