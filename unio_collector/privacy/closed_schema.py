"""Exact typed privacy traversal shared only by explicitly recognized producers."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar

from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

PREFIX = "$.scanner_evidence[].payload"


class ClosedProducerContract:
    """Preflight every path before any profile can omit a recognized payload."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {}

    def unknown_record_paths(self, record: dict[str, Any], member: str) -> list[str]:
        """Reject undeclared envelope members as well as payload descendants."""
        fields = {
            "bundle_schema_version",
            "scanner_id",
            "serialization_status",
            "serialization_format",
            "evidence_type",
            "evidence_module",
            "payload",
            "limitations",
            "provider_id",
            "evidence_schema_id",
            "evidence_schema_version",
        }
        errors = [member + ".scanner_evidence[]." + key for key in record if key not in fields]
        return errors + self.unknown_paths(record.get("payload"), member)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject unknown and wrongly typed containers before strict omission."""
        spec = self.fields.get(suffix)
        path = member + PREFIX[1:] + ("." + suffix if suffix else "")
        if spec is None or not self._valid(value, spec[0], nullable=spec[2]):
            return [path]
        if isinstance(value, dict):
            failures: list[str] = []
            for key, child in value.items():
                child_suffix = suffix + ("." if suffix else "") + key

                if any(character in key for character in ".[]"):
                    failures.append(member + PREFIX[1:] + "." + child_suffix)
                else:
                    failures.extend(self.unknown_paths(child, member, child_suffix))
            return failures
        if isinstance(value, list):
            return [failure for child in value for failure in self.unknown_paths(child, member, suffix + "[]")]
        return []

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Return one exact payload decision or block its unknown descendant."""
        if path != PREFIX and not path.startswith((PREFIX + ".", PREFIX + "[")):
            return None
        suffix = path[len(PREFIX) :].removeprefix(".")
        spec = self.fields.get(suffix)
        category = spec[1] if spec else None
        treatment = (
            "unsupported"
            if spec is None
            else "remove"
            if category == "removed_diagnostic" or (category == "cost" and profile == "strict")
            else "tokenise"
            if category in {"aws_account_id", "resource_name", "resource_id", "arn", "bucket_name", "arn_or_name"}
            else "generalise"
            if category in {"region", "timestamp"} and profile == "strict"
            else "profile_configurable"
            if category in {"region", "timestamp", "free_text"}
            else "preserve"
        )
        return PrivacyTreatmentDecision(
            treatment=treatment,
            category=category,
            canonicaliser_id=None,
            canonicaliser_version=None,
            fallback_allowed=False,
            decision_source="unsupported" if spec is None else "exact_json_path",
            reason="Closed recognized producer contract; unknown paths are not admitted.",
        )

    def mapping_key_category(self, path: str) -> str | None:
        """Declare protected dynamic keys only for an exact typed-map contract."""
        del path
        return None

    def is_tag_record(self, path: str) -> bool:
        """Identify only explicitly declared provider tag-record containers."""
        del path
        return False

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Allow exact producer contracts to distinguish public constants from identities."""
        del value
        return self.resolve(path, profile)

    @staticmethod
    def _valid(value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "object":
            return isinstance(value, dict)
        if kind == "array":
            return isinstance(value, list)
        if kind == "string":
            return isinstance(value, str)
        if kind == "boolean":
            return type(value) is bool
        if kind == "count":
            return type(value) is int and value >= 0
        if kind == "money" and type(value) in {str, int, float}:
            try:
                return Decimal(str(value)).is_finite()
            except InvalidOperation:
                return False
        return False
