"""Context-specific metadata versus identity handling for CloudTrail selectors."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.audit.fields import SELECTOR, VOCABULARIES
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

FIELD_NAMES = frozenset(
    {
        "eventCategory",
        "resources.type",
        "resources.ARN",
        "eventSource",
        "eventName",
        "eventType",
        "readOnly",
        "userIdentity.arn",
        "errorCode",
        "sessionCredentialFromConsole",
    }
)
OPERATOR_NAMES = frozenset({"Equals", "StartsWith", "EndsWith", "NotEquals", "NotStartsWith", "NotEndsWith"})


class AuditConditionContract(ClosedProducerContract):
    """Preserve finite category/boolean literals only in their actual selector context."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        prefix + "." + path: spec
        for prefix in ("records[].raw_selectors[]", "records[].raw_event_data_stores[].advanced_selectors[]")
        for path, spec in SELECTOR.items()
    }

    def __init__(self, field: str) -> None:
        """Bind one actual container; do not pool values across array elements."""
        self.field = field

    def is_literal(self, suffix: str, value: str) -> bool:
        """Recognize field names and exact finite Equals/NotEquals metadata values."""
        if suffix not in self.fields:
            return False
        if suffix.endswith(".field_conditions[].field"):
            return value in FIELD_NAMES
        operator = suffix.rsplit(".", maxsplit=1)[-1].removesuffix("[]")
        if operator not in {"Equals", "NotEquals"}:
            return False
        if self.field == "eventCategory":
            return value in VOCABULARIES["event_category"]
        return self.field in {"readOnly", "sessionCredentialFromConsole"} and value in {"true", "false"}

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect arbitrary condition strings and identifiers as whole values."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep metadata Data distinct from a customer identifier with the same spelling."""
        decision = self.resolve(path, profile)
        if decision is not None and self.is_literal(path.removeprefix(PREFIX + "."), value):
            return replace(decision, treatment="preserve", category="safe_metadata")
        return decision
