from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsIamConditionSpecification:
    """One audited IAM condition supported by an action-scope variant."""

    operator: str
    key: str
    value_templates: tuple[str, ...]
    required_variables: tuple[str, ...]
    rationale: str
    authorization_reference: str


__all__ = ["AwsIamConditionSpecification"]
