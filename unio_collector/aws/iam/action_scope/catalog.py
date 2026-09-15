"""Versioned AWS IAM action-scope catalogue."""

from __future__ import annotations

from unio_collector.aws.iam.action_scope import (
    AwsIamActionScopeDefinition,
    AwsIamConditionSpecification,
    AwsIamScopeVariant,
)

AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION = "2026-08"
AWS_SERVICE_AUTHORIZATION_REFERENCE = "https://docs.aws.amazon.com/service-authorization/latest/reference/"
AWS_GLOBAL_CONDITION_REFERENCE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-requestedregion"


def get_aws_iam_action_scope(api_action: str) -> AwsIamActionScopeDefinition:
    """Return the shared authorization definition for an AWS action."""
    if api_action in _CURATED_DEFINITIONS:
        return _CURATED_DEFINITIONS[api_action]
    return _unresolved_definition(api_action)


def _definition(
    api_action: str,
    *,
    resource_types: tuple[str, ...],
    arn_templates: tuple[str, ...],
    required_variables: tuple[str, ...],
    wildcard_required: bool,
    rationale: str,
    conditions: tuple[AwsIamConditionSpecification, ...] = (),
) -> AwsIamActionScopeDefinition:
    variant_id = api_action.casefold().replace(":", "-") + "-default"
    return AwsIamActionScopeDefinition(
        api_action=api_action,
        catalogue_schema_version=AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION,
        variants=(
            AwsIamScopeVariant(
                variant_id=variant_id,
                resource_types=resource_types,
                arn_templates=arn_templates,
                required_variables=required_variables,
                conditions=conditions,
                dependent_constraints=(),
                wildcard_required=wildcard_required,
                rationale=rationale,
                authorization_references=(AWS_SERVICE_AUTHORIZATION_REFERENCE,),
            ),
        ),
    )


def _wildcard(api_action: str, rationale: str) -> AwsIamActionScopeDefinition:
    return _definition(
        api_action,
        resource_types=(),
        arn_templates=("*",),
        required_variables=(),
        wildcard_required=True,
        rationale=rationale,
    )


def _regional_condition() -> tuple[AwsIamConditionSpecification, ...]:
    return (
        AwsIamConditionSpecification(
            operator="StringEquals",
            key="aws:RequestedRegion",
            value_templates=("{regions}",),
            required_variables=("regions",),
            rationale=("The AWS global aws:RequestedRegion condition key constrains the regional endpoint used for this audited EC2 read operation."),
            authorization_reference=AWS_GLOBAL_CONDITION_REFERENCE,
        ),
    )


def _unresolved_definition(api_action: str) -> AwsIamActionScopeDefinition:
    variant_id = api_action.casefold().replace(":", "-") + "-unresolved"
    return AwsIamActionScopeDefinition(
        api_action=api_action,
        catalogue_schema_version=AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION,
        variants=(
            AwsIamScopeVariant(
                variant_id=variant_id,
                resource_types=(),
                arn_templates=(),
                required_variables=("authorization_scope",),
                conditions=(),
                dependent_constraints=("Authoritative AWS action-level resource and condition semantics require review.",),
                wildcard_required=False,
                rationale=("Unio Collector has not yet audited a safe deployable resource scope for this action; policy rendering must fail closed."),
                authorization_references=(AWS_SERVICE_AUTHORIZATION_REFERENCE,),
                unresolved=True,
            ),
        ),
    )


_S3_BUCKET_ACTIONS = (
    "s3:GetBucketAcl",
    "s3:GetBucketLocation",
    "s3:GetBucketNotification",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetPublicAccessBlock",
    "s3:GetReplicationConfiguration",
    "s3:ListBucketMultipartUploads",
)

_CURATED_DEFINITIONS = {
    **{
        action: _definition(
            action,
            resource_types=("bucket",),
            arn_templates=("arn:{partition}:s3:::*",),
            required_variables=("partition",),
            wildcard_required=False,
            rationale=("AWS Service Authorization Reference supports bucket resources for this action; Unio Collector plans access to bucket ARNs only."),
        )
        for action in _S3_BUCKET_ACTIONS
    },
    "s3:GetObject": AwsIamActionScopeDefinition(
        api_action="s3:GetObject",
        catalogue_schema_version=AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION,
        variants=(
            AwsIamScopeVariant(
                variant_id="s3-getobject-object",
                resource_types=("object",),
                arn_templates=("arn:{partition}:s3:::*/*",),
                required_variables=("partition",),
                conditions=(),
                dependent_constraints=(),
                wildcard_required=False,
                rationale=("AWS Service Authorization Reference supports S3 object resources for GetObject."),
                authorization_references=(AWS_SERVICE_AUTHORIZATION_REFERENCE,),
            ),
            AwsIamScopeVariant(
                variant_id="s3-getobject-access-point-object",
                resource_types=("accesspointobject",),
                arn_templates=("arn:{partition}:s3:{region}:{account_id}:accesspoint/{access_point}/object/*",),
                required_variables=(
                    "partition",
                    "region",
                    "account_id",
                    "access_point",
                ),
                conditions=(),
                dependent_constraints=("Use only when collection is explicitly configured through an S3 access point.",),
                wildcard_required=False,
                rationale=("AWS documents access-point object ARNs as a distinct GetObject authorization resource type."),
                authorization_references=(AWS_SERVICE_AUTHORIZATION_REFERENCE,),
            ),
        ),
    ),
    "s3:ListAllMyBuckets": _wildcard(
        "s3:ListAllMyBuckets",
        "AWS does not support resource-level permissions for ListAllMyBuckets.",
    ),
    "sts:GetCallerIdentity": _wildcard(
        "sts:GetCallerIdentity",
        "STS GetCallerIdentity does not support resource-level permissions.",
    ),
    "ce:GetCostAndUsage": _wildcard(
        "ce:GetCostAndUsage",
        "Cost Explorer GetCostAndUsage does not support resource-level permissions.",
    ),
    "cloudwatch:GetMetricData": _wildcard(
        "cloudwatch:GetMetricData",
        "CloudWatch GetMetricData does not support resource-level permissions.",
    ),
    "cloudwatch:GetMetricStatistics": _wildcard(
        "cloudwatch:GetMetricStatistics",
        "CloudWatch GetMetricStatistics does not support resource-level permissions.",
    ),
    "ec2:DescribeInstances": _definition(
        "ec2:DescribeInstances",
        resource_types=(),
        arn_templates=("*",),
        required_variables=(),
        wildcard_required=True,
        rationale="EC2 DescribeInstances requires wildcard resource scope.",
        conditions=_regional_condition(),
    ),
    "ec2:DescribeRegions": _wildcard(
        "ec2:DescribeRegions",
        "EC2 DescribeRegions does not support resource-level permissions.",
    ),
    "tag:GetResources": _wildcard(
        "tag:GetResources",
        "Resource Groups Tagging API GetResources does not support resource-level permissions.",
    ),
    "application-autoscaling:DescribeScalableTargets": _wildcard(
        "application-autoscaling:DescribeScalableTargets",
        "Application Auto Scaling DescribeScalableTargets does not support resource-level permissions.",
    ),
    "application-autoscaling:DescribeScalingPolicies": _wildcard(
        "application-autoscaling:DescribeScalingPolicies",
        "Application Auto Scaling DescribeScalingPolicies does not support resource-level permissions.",
    ),
    "dynamodb:ListTables": _wildcard(
        "dynamodb:ListTables",
        "DynamoDB ListTables does not support resource-level permissions.",
    ),
    **{
        action: _definition(
            action,
            resource_types=("table",),
            arn_templates=("arn:{partition}:dynamodb:{region}:{account_id}:table/*",),
            required_variables=("partition", "regions", "account_id"),
            wildcard_required=False,
            rationale=("AWS Service Authorization Reference supports DynamoDB table resources for this read operation."),
        )
        for action in (
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:ListTagsOfResource",
        )
    },
}


__all__ = [
    "AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION",
    "get_aws_iam_action_scope",
]
