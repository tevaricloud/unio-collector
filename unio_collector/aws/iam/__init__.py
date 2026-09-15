"""AWS IAM authorization-scope contracts."""

from unio_collector.aws.iam.action_scope import (
    AwsIamActionScopeDefinition,
    AwsIamConditionSpecification,
    AwsIamScopeVariant,
)
from unio_collector.aws.iam.action_scope.catalog import (
    AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION,
    get_aws_iam_action_scope,
)

__all__ = [
    "AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION",
    "AwsIamActionScopeDefinition",
    "AwsIamConditionSpecification",
    "AwsIamScopeVariant",
    "get_aws_iam_action_scope",
]
