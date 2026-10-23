"""Exact registered AWS-native source envelope and resource-specific privacy."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.recommendation.errors import PUBLIC_ERROR_CODES
from unio_collector.privacy.recommendation.fields import SCANNERS, SOURCE_TYPES, VOCABULARIES
from unio_collector.privacy.recommendation.records import select_recommendation_record
from unio_collector.privacy.recommendation.sdk.vocabulary import VOCABULARIES as SDK_VOCABULARIES
from unio_collector.privacy.recommendation.values import public_number, valid_value
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class RecommendationPrivacyContract(ClosedProducerContract):
    """Protect actual populated provider recommendations and retained fixtures."""

    scanner_id: ClassVar[str] = ""

    def __init__(self, source: str = "") -> None:
        """Bind one concrete source/resource field view without shared mutation."""
        self.source = source

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require exact registered AWS dictionary identity before field admission."""
        scanner = record.get("scanner_id")
        if not isinstance(scanner, str) or scanner not in SCANNERS or scanner != cls.scanner_id:
            return None
        if (
            record.get("provider_id", "aws") != "aws"
            or admit_evidence_schema(record) is not None
            or (record.get("evidence_module"), record.get("evidence_type")) != ("builtins", "dict")
            or record.get("serialization_status") != "serialized"
            or record.get("serialization_format") != "json-compatible-python-object"
        ):
            message = "AWS-native privacy requires its exact registered source identity."
            raise ValueError(message)
        payload = record.get("payload")
        if not isinstance(payload, dict) or payload.get("source", SCANNERS[scanner]) != SCANNERS[scanner]:
            message = "AWS-native privacy source identity is conflicting."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        specialized = valid_value(value, kind, nullable=nullable)
        return specialized if specialized is not None else super()._valid(value, kind, nullable=nullable)

    def for_container(self, value: dict[str, Any], path: str) -> ClosedProducerContract | None:
        """Select record schemas only using the preserved source/resource discriminator."""
        if path != self.prefix + ".records[]" or value.get("source") != self.source:
            return None
        kind = value.get("recommendation_type") if self.source == "compute_optimizer" else "hub"
        if not isinstance(kind, str) or (kind not in SOURCE_TYPES and kind != "hub") or (self.source == "compute_optimizer" and kind not in SOURCE_TYPES):
            return None
        if self.source == "compute_optimizer" and (value.get("service"), value.get("resource_type")) != SOURCE_TYPES[kind]:
            return None
        return select_recommendation_record(kind)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject every unknown descendant, including financial fields strict removes."""
        if suffix == "records[]" and isinstance(value, dict):
            contract = self.for_container(value, self.prefix + "." + suffix)
            if contract is None:
                return [member + self.prefix[1:] + ".records[].recommendation_type"]
            return contract.unknown_paths(value, member, suffix)
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "" and isinstance(value, dict):
            if value.get("source", self.source) != self.source:
                failures.append(member + self.prefix[1:] + ".source")
            required = {"account_id", "regions", "warnings", "records"}
            if value.get("evidence_version") == 1:
                required |= {"source", "status", "recommendation_count", "summary_count", "summaries", "limitations", "metadata"}
            failures.extend(member + self.prefix[1:] + "." + key for key in sorted(required - value.keys()))
            for key, rows in (("recommendation_count", "records"), ("summary_count", "summaries")):
                if key in value and isinstance(value.get(rows), list) and value[key] != len(value[rows]):
                    failures.append(member + self.prefix[1:] + "." + key)
        return failures

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Retain declared operational codes; arbitrary error text still protects."""
        decision = self.resolve(path, profile)
        suffix = path[len(self.prefix) :].removeprefix(".")
        if decision is not None and suffix == "metadata.operation_statuses[].error_code" and value in PUBLIC_ERROR_CODES:
            return replace(decision, treatment="preserve", category="safe_metadata", reason="Finite identity-bound recommendation reader code.")
        return decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Only declared finite control/enumeration fields are non-customer literals."""
        if suffix == "metadata.operation_statuses[].error_code" and suffix in self.fields:
            return value in PUBLIC_ERROR_CODES
        spec = self.fields.get(suffix)
        if spec is None or spec[1] != "safe_metadata":
            return False
        choices = VOCABULARIES.get(spec[0]) or SDK_VOCABULARIES.get(spec[0], frozenset())
        return value in choices

    def is_public_number(self, suffix: str, value: object) -> bool:
        """Use only the concrete source/resource operational-number declaration."""
        return public_number(value, self.fields.get(suffix))
