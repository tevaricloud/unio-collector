"""AWS IAM action-scope contracts and catalogue."""

from unio_collector.aws.iam.action_scope.condition import AwsIamConditionSpecification
from unio_collector.aws.iam.action_scope.definition import AwsIamActionScopeDefinition
from unio_collector.aws.iam.action_scope.variant import AwsIamScopeVariant

__all__ = [
    "AwsIamActionScopeDefinition",
    "AwsIamConditionSpecification",
    "AwsIamScopeVariant",
]
