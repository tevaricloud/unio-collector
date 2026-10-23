"""Bind nested configuration fields to the actual source and resource operation."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.recommendation.fields import RECORD_FIELDS, SOURCE_TYPES
from unio_collector.privacy.recommendation.sdk.vocabulary import VOCABULARIES
from unio_collector.privacy.recommendation.sdk_fields import RECORD_FIELDS as SDK_FIELDS
from unio_collector.privacy.recommendation.values import public_number, valid_value

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class RecommendationRecordContract(ClosedProducerContract):
    """Admit only declared fields of one normalized provider recommendation."""

    def __init__(self, source: str, kind: str) -> None:
        """Bind one concrete source/resource field view without shared mutation."""
        self.source = source
        self.kind = kind

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        specialized = valid_value(value, kind, nullable=nullable)
        return specialized if specialized is not None else super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Validate record identity and complete dataclass fields before transformation."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "records[]" and isinstance(value, dict):
            required = {path[len("records[].") :] for path in RECORD_FIELDS if path.startswith("records[].")}
            failures.extend(member + self.prefix[1:] + "." + suffix + "." + key for key in sorted(required - value.keys()))
            if value.get("source") != self.source:
                failures.append(member + self.prefix[1:] + "." + suffix + ".source")
            if self.source == "compute_optimizer" and (
                value.get("recommendation_type") != self.kind or (value.get("service"), value.get("resource_type")) != SOURCE_TYPES[self.kind]
            ):
                failures.append(member + self.prefix[1:] + "." + suffix + ".recommendation_type")
        return failures

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep finite public provider roles; arbitrary text still tokenizes entirely."""
        decision = self.resolve(path, profile)
        if decision is None:
            return None
        suffix = path[len(self.prefix) :].removeprefix(".")
        literal = (
            (suffix == "records[].source" and value == self.source)
            or (
                self.source == "compute_optimizer"
                and (
                    (suffix == "records[].recommendation_type" and value == self.kind)
                    or (suffix in {"records[].service", "records[].resource_type"} and value in SOURCE_TYPES[self.kind])
                )
            )
            or (suffix == "records[].service" and self.source == "cost_optimization_hub" and value in {"AWS", "Amazon EC2", "Amazon RDS"})
        )
        if self.source == "cost_optimization_hub":
            literal = literal or (suffix, value) in {("records[].recommendation_type", "recommendation"), ("records[].resource_type", "AWS resource")}
        if suffix == "records[].finding" and self.source == "compute_optimizer":
            literal = literal or value in self.provider_findings()
        if literal:
            return replace(
                decision,
                treatment="preserve",
                category="safe_metadata",
                reason="Exact source-bound provider protocol role; arbitrary identifiers are not literals.",
            )
        if decision.category == "cost" and suffix.endswith((".currency", ".currencyCode")) and value not in {"USD", "EUR", "GBP"} and profile == "standard":
            return replace(decision, treatment="tokenise", category="resource_name", reason="Unrecognized currency text protects; strict removal remains.")
        return decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Mask only admitted enums and exact source-bound fixed protocol roles."""
        spec = self.fields.get(suffix)
        if (
            self.source == "compute_optimizer"
            and self.kind == "rds_database"
            and suffix
            in {
                "records[].raw_summary.currentStorageEstimatedMonthlyVolumeIOPsCostVariation",
                "records[].recommended_configuration.estimatedMonthlyVolumeIOPsCostVariation",
            }
            and spec == ("sdk_RDSEstimatedMonthlyVolumeIOPsCostVariation", "cost", False)
        ):
            return value in VOCABULARIES["sdk_RDSEstimatedMonthlyVolumeIOPsCostVariation"]
        if spec and spec[1] == "safe_metadata" and spec[0] in VOCABULARIES:
            return value in VOCABULARIES[spec[0]]
        decision = self.resolve_string(self.prefix + "." + suffix, value, "standard")
        return (
            decision is not None
            and decision.category == "safe_metadata"
            and decision.treatment == "preserve"
            and (
                suffix == "records[].source" or suffix in {"records[].recommendation_type", "records[].service", "records[].resource_type", "records[].finding"}
            )
        )

    def is_public_number(self, suffix: str, value: object) -> bool:
        """Use only the concrete source/resource operational-number declaration."""
        return public_number(value, self.fields.get(suffix))

    def provider_findings(self) -> frozenset[str]:
        """Return only actual SDK categorical findings for this exact resource type."""
        if self.source != "compute_optimizer":
            return frozenset()
        declared = SDK_FIELDS[self.kind]
        keys = ("raw_summary.finding", "raw_summary.instanceFinding", "raw_summary.storageFinding")
        return frozenset(value for key in keys if (spec := declared.get(key)) is not None for value in VOCABULARIES.get(spec[0], frozenset()))
