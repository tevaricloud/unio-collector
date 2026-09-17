from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.iam.action_scope.condition import AwsIamConditionSpecification


@dataclass(frozen=True)
class AwsIamScopeVariant:
    """One audited authorization form for an AWS IAM action."""

    variant_id: str
    resource_types: tuple[str, ...]
    arn_templates: tuple[str, ...]
    required_variables: tuple[str, ...]
    conditions: tuple[AwsIamConditionSpecification, ...]
    dependent_constraints: tuple[str, ...]
    wildcard_required: bool
    rationale: str
    authorization_references: tuple[str, ...]
    unresolved: bool = False


__all__ = ["AwsIamScopeVariant"]
