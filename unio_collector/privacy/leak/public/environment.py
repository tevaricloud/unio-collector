"""Position-bound scan view for generated canonical environment context only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError

from unio_collector.environment.context import EnvironmentContext

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract

MARKERS = frozenset({"tags", "target_tags", "current_tags", "associated_tags", "resource_name", "resource_id", "arn"})
REQUIRED = frozenset({"classifier_version", "classification", "evidence_strength"})


class EnvironmentContextScanContract:
    """Recognize complete public context under an already selected closed producer parent."""

    @classmethod
    def validation_view(cls, value: object, contract: ClosedProducerContract, suffix: str) -> object:
        """Exclude only complete generated context from a separate shape-validation copy."""
        if isinstance(value, dict) and "environment_context" in value and cls.admitted(value, contract, suffix):
            return {key: child for key, child in value.items() if key != "environment_context"}
        return value

    @staticmethod
    def admitted(parent: dict[str, object], contract: ClosedProducerContract, suffix: str) -> bool:
        """Never traverse unknown containers or normalize customer fields by their values."""
        spec = contract.fields.get(suffix)
        if spec is None or spec[0] != "object":
            return False
        prefix = suffix + "." if suffix else ""
        if not any(prefix + marker in contract.fields for marker in MARKERS):
            return False
        context = parent.get("environment_context")
        if not isinstance(context, dict) or set(context) not in (REQUIRED, REQUIRED | {"canonical_subtype"}):
            return False
        if not all(isinstance(value, str) for value in context.values()):
            return False
        try:
            EnvironmentContext.model_validate(context)
        except ValidationError:
            return False
        return True
