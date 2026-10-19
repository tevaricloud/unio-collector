"""Closed producer identities, nullable fields and finite vocabularies for IAM."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.identity.fields import SCANNERS, VOCABULARIES
from unio_collector.privacy.identity.policy import invalid_policy_shape

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class IdentityPrivacyContract(AuditPrivacyContract):
    """Protect identifiers and free text; unknown provider metadata stays blocked."""

    identities: ClassVar = SCANNERS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "strings":
            return (isinstance(value, str) and bool(value.strip())) or (
                isinstance(value, list) and bool(value) and all(isinstance(child, str) and bool(child.strip()) for child in value)
            )
        if kind == "statement":
            return isinstance(value, dict) or (isinstance(value, list) and bool(value) and all(isinstance(child, dict) for child in value))
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: str) -> bool:
        """Keep finite metadata distinct from customer strings at exact positions."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in VOCABULARIES and value in VOCABULARIES[spec[0]]

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Admit only typed region-status keys and service-specific metadata names."""
        if suffix == "analyzer_inventory_status":
            valid = isinstance(value, dict) and all(
                self.region_key(key) and self._valid(status, "inventory_status", nullable=False) for key, status in value.items()
            )
            return [] if valid else [member + PREFIX[1:] + "." + suffix]
        failures = super().unknown_paths(value, member, suffix)
        if invalid_policy_shape(value, suffix):
            failures.append(member + PREFIX[1:] + "." + suffix)
        if suffix == "records[]" and isinstance(value, dict) and self.scanner_id == "aws-security-service-coverage-review":
            allowed = {
                "CloudTrail": {"visible_trail_count", "multi_region_trail_count", "organization_trail_count"},
                "AWS Config": {"recorder_count", "recording", "aggregator_count", "aggregator_names", "conformance_pack_count", "conformance_pack_names"},
                "GuardDuty": set(),
                "Security Hub": set(),
            }
            metadata = value.get("metadata")
            if isinstance(metadata, dict):
                failures.extend(
                    member + PREFIX[1:] + ".records[].metadata." + key for key in metadata if key not in allowed.get(str(value.get("service_name")), set())
                )
        return failures

    @staticmethod
    def region_key(key: object) -> bool:
        """Validate the typed regional inventory map, excluding field/path syntax."""
        return isinstance(key, str) and re.fullmatch(r"(?:us|eu|ap|sa|ca|me|af|il|mx|cn)(?:-[a-z]+)+-[0-9]+", key) is not None

    def mapping_key_category(self, path: str) -> str | None:
        """Protect regional map keys consistently without admitting other maps."""
        return "region" if path == PREFIX + ".analyzer_inventory_status" else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Resolve only actual region-status map values beyond fixed DTO fields."""
        from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision  # noqa: PLC0415

        suffix = path.removeprefix(PREFIX + ".")
        if suffix.startswith("analyzer_inventory_status.") and self.region_key(suffix.removeprefix("analyzer_inventory_status.")):
            return PrivacyTreatmentDecision(
                treatment="preserve",
                category="safe_metadata",
                canonicaliser_id=None,
                canonicaliser_version=None,
                fallback_allowed=False,
                decision_source="exact_json_path",
                reason="Typed regional inventory status from the identity-bound Access Analyzer producer.",
            )
        return super().resolve(path, profile)
