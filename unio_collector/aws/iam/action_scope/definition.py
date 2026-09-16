from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.iam.action_scope.variant import AwsIamScopeVariant


@dataclass(frozen=True)
class AwsIamActionScopeDefinition:
    """Shared AWS authorization semantics for one IAM action."""

    api_action: str
    catalogue_schema_version: str
    variants: tuple[AwsIamScopeVariant, ...]

    def get_variant(self, variant_id: str) -> AwsIamScopeVariant:
        """Return one declared variant or fail closed."""
        for variant in self.variants:
            if variant.variant_id == variant_id:
                return variant
        msg = f"AWS IAM action {self.api_action} has no scope variant {variant_id}."
        raise ValueError(msg)


__all__ = ["AwsIamActionScopeDefinition"]
