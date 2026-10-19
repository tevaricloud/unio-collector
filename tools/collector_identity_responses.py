"""Finite synthetic SDK shapes for actual IAM and security-service collection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def responses(service: str, variant: str, parameters: dict[str, object]) -> dict[str, dict[str, Any]]:
    """Return populated provider response shapes, never credentials or AWS clients."""
    name = (
        str(parameters.get("scanner"))
        if variant == "identity_collision"
        else "Allow"
        if variant == "policy_collision"
        else "ACTIVE"
        if variant == "collision"
        else "complete"
        if variant == "name_complete"
        else "eu-west-2"
        if variant == "name_region"
        else "synthetic-customer-identity"
    )
    timestamp = datetime(2026, 1, 2, tzinfo=UTC)
    nullable = variant == "nullable"
    if service == "iam":
        policy = {
            "Version": "2012-10-17",
            "Id": name,
            "Statement": [
                {
                    "Sid": name,
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "kms:Decrypt"],
                    "Resource": ["arn:aws:s3:::synthetic-customer/*"],
                    "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/synthetic-customer"}},
                },
                {"Effect": "Deny", "NotAction": "iam:*", "NotResource": "*"},
            ],
        }
        if variant == "statement_object":
            policy["Statement"] = policy["Statement"][0]
        result = {
            "get_account_summary": {"SummaryMap": dict.fromkeys(SUMMARY_KEYS, 1)},
            "get_account_password_policy": {
                "PasswordPolicy": {
                    "MinimumPasswordLength": 14,
                    "RequireSymbols": True,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    **(
                        {}
                        if nullable
                        else {
                            "AllowUsersToChangePassword": True,
                            "ExpirePasswords": True,
                            "MaxPasswordAge": 90,
                            "PasswordReusePrevention": 12,
                            "HardExpiry": False,
                        }
                    ),
                }
            },
            "list_users": {
                "Users": [
                    {
                        "UserName": name,
                        **({} if nullable else {"UserId": name, "Arn": "arn:aws:iam::123456789012:user/synthetic-customer", "PasswordLastUsed": timestamp}),
                    }
                ]
            },
            "get_login_profile": {"LoginProfile": {"UserName": name, "CreateDate": timestamp}},
            "list_mfa_devices": {"MFADevices": [{"SerialNumber": "synthetic-only-device"}]},
            "list_access_keys": {
                "AccessKeyMetadata": [
                    {"AccessKeyId": name, "Status": "Active", **({} if nullable else {"CreateDate": timestamp})},
                    {"AccessKeyId": "synthetic-inactive-identifier", "Status": "Inactive"},
                ]
            },
            "get_access_key_last_used": {
                "AccessKeyLastUsed": {"ServiceName": "s3", "Region": "eu-west-2", **({} if nullable else {"LastUsedDate": timestamp})}
            },
            "list_entities_for_policy": {"PolicyUsers": [{"UserName": name}], "PolicyGroups": [{"GroupName": name}], "PolicyRoles": [{"RoleName": name}]},
            "list_groups": {"Groups": [{"GroupName": name, "Arn": "arn:aws:iam::123456789012:group/synthetic-customer"}]},
            "list_roles": {"Roles": [{"RoleName": name, "Arn": "arn:aws:iam::123456789012:role/synthetic-customer"}]},
        }
        for kind in ("user", "group", "role"):
            result["list_" + kind + "_policies"] = {"PolicyNames": [name]}
            result["get_" + kind + "_policy"] = {"PolicyDocument": policy}
        return result
    if service == "accessanalyzer":
        arn = "arn:aws:access-analyzer:eu-west-2:123456789012:analyzer/synthetic-customer"
        finding = {
            "id": name,
            "status": "ACTIVE",
            **(
                {}
                if nullable
                else {
                    "findingType": "ExternalAccess",
                    "resource": "arn:aws:s3:::synthetic-customer",
                    "resourceType": "AWS::S3::Bucket",
                    "principal": {"AWS": "123456789012"},
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                }
            ),
        }
        return {
            "list_analyzers": {"analyzers": [{"name": name, "arn": arn, "status": "ACTIVE", **({} if nullable else {"type": "ACCOUNT"})}]},
            "list_findings_v2": {"findings": [finding, {"id": "synthetic-archived", "status": "ARCHIVED"}]},
        }
    if service == "sso-admin":
        instance = "arn:aws:sso:::instance/ssoins-synthetic"
        permission = "arn:aws:sso:::permissionSet/ssoins-synthetic/ps-synthetic"
        return {
            "list_instances": {
                "Instances": [
                    {
                        "InstanceArn": instance,
                        **(
                            {}
                            if nullable
                            else {"IdentityStoreId": name, "OwnerAccountId": "123456789012", "Name": name, "Status": "ACTIVE", "CreatedDate": timestamp}
                        ),
                    }
                ]
            },
            "list_permission_sets": {"PermissionSets": [permission]},
            "describe_permission_set": {
                "PermissionSet": {
                    "Name": name,
                    **(
                        {}
                        if nullable
                        else {
                            "Description": "synthetic customer arbitrary permission prose",
                            "SessionDuration": "PT8H",
                            "RelayState": "https://synthetic.invalid/relay",
                        }
                    ),
                }
            },
            "list_managed_policies_in_permission_set": {"AttachedManagedPolicies": [{"Arn": "arn:aws:iam::aws:policy/AdministratorAccess"}]},
            "list_customer_managed_policy_references_in_permission_set": {"CustomerManagedPolicyReferences": [{"Name": name, "Path": "/synthetic/"}]},
        }
    if service == "cloudtrail":
        return {"describe_trails": {"trailList": [{"IsOrganizationTrail": True, "IsMultiRegionTrail": True}]}}
    if service == "config":
        return {
            "describe_configuration_recorders": {"ConfigurationRecorders": [{"name": name}]},
            "describe_configuration_recorder_status": {
                "ConfigurationRecordersStatus": [{"name": "synthetic-nonmatching" if nullable else name, "recording": True}]
            },
            "describe_configuration_aggregators": {"ConfigurationAggregators": [{"ConfigurationAggregatorName": name}]},
            "describe_conformance_packs": {"ConformancePackDetails": [{"ConformancePackName": name}]},
        }
    if service == "guardduty":
        return {"list_detectors": {"DetectorIds": [name]}}
    if service == "securityhub":
        return {
            "describe_hub": {},
            "get_enabled_standards": {"StandardsSubscriptions": [{"StandardsArn": "arn:aws:securityhub:eu-west-2::standards/synthetic"}]},
        }
    message = "Unexpected synthetic identity endpoint"
    raise AssertionError(message)


SUMMARY_KEYS = (
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
)


def shape_response(value: dict[str, Any], variant: str, operation: str, scanner: str) -> dict[str, Any]:
    """Exercise only admission/absence shapes supported by the invoked collector."""
    del scanner
    if variant == "empty":
        return {key: [] if isinstance(child, list) else child for key, child in value.items()}
    if variant == "malformed" and operation == "list_users":
        return {"Users": "synthetic-malformed-container"}
    if variant == "malformed" and operation in {"list_users", "list_analyzers", "list_instances", "describe_trails"}:
        return {key: [{}] if isinstance(child, list) else child for key, child in value.items()}
    if variant == "truncated" and operation in {"list_users", "list_analyzers", "list_instances", "describe_trails", "list_permission_sets"}:
        return dict(value, **({"nextToken": "synthetic-next"} if operation == "list_analyzers" else {"NextToken": "synthetic-next"}))
    return value
