"""Closed identity-bound DynamoDB counts, samples and optional cost observations."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.dynamodb.fields import FIELDS, METRICS, SCANNER

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class DynamoPrivacyContract(AuditPrivacyContract):
    """Protect sampled names and arbitrary text, preserving factual metrics and strict costs."""

    scanner_id: ClassVar[str] = SCANNER
    identities: ClassVar = {SCANNER: ("dynamodb.cost_governance.evidence", "DynamoDbCostGovernanceEvidence", {})}
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Require producer identity fields while admitting only declared DTO defaults."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "records[]" and isinstance(value, dict) and not {"account_id", "region"}.issubset(value):
            failures.append(member + self.prefix[1:] + ".records[]")
        return failures

    def admitted_scan_record(self, value: object) -> bool:
        """Validate exact strict money redactions in a copy; raw preflight stays strict."""
        if not isinstance(value, dict):
            return False
        checked = dict(value)
        for key, child in value.items():
            spec = self.fields.get("records[]." + key)
            if spec == ("money", "cost", True) and child == "":
                checked[key] = None
        return not self.unknown_paths(checked, "", "records[]")

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Apply the same profile-specific tag-key policy to sampled keys and map keys."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "tag_key" else decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Recognise only actual finite CloudWatch metric names at their bound role."""
        return suffix == "records[].observed_metric_names[]" and isinstance(value, str) and value in METRICS

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Retain finite metric labels without exempting arbitrary strings."""
        decision = self.resolve(path, profile)
        return (
            replace(decision, treatment="preserve", category="safe_metadata")
            if decision is not None and self.is_literal(path.removeprefix(self.prefix + "."), value)
            else decision
        )
