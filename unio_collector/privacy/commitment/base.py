"""Typed admission and exact public controls for commitment observations."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.commitment.fields import FIELDS
from unio_collector.privacy.commitment.scan import CommitmentScanAdmission
from unio_collector.privacy.commitment.vocabulary import CURRENCIES, GROUPINGS, PUBLIC_ROLES, VOCABULARIES

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


PAIR_SIZE = 2


class CommitmentPrivacyBase(AuditPrivacyContract):
    """Protect provider text and financial values without trusting arbitrary literals."""

    fields: ClassVar = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Require exact finite controls and two-string tuples; reject unsupported legacy list contents."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "pair":
            return (
                isinstance(value, list)
                and len(value) == PAIR_SIZE
                and all(isinstance(item, str) for item in value)
                and (value[0] != "_grouping" or value[1] in GROUPINGS)
            )
        if kind == "empty_array":
            return value == []
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: object) -> bool:
        """Allow only independently declared control roles and typed non-financial durations/counts."""
        spec = self.fields.get(suffix)
        if spec is None:
            return False
        if spec[0] in VOCABULARIES:
            return self._valid(value, spec[0], nullable=False)
        if spec[1] == "summary_count":
            return type(value) is int and value >= 0
        return isinstance(value, str) and value in PUBLIC_ROLES.get(suffix.rsplit(".", maxsplit=1)[-1], ())

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Apply whole-value protection except exact supported public controls."""
        decision = super().resolve_string(path, value, profile)
        suffix = path.removeprefix(self.prefix + ".")
        if decision is not None and suffix in {"portfolio.inventory[].payment.currency", "portfolio.observed_metrics[].currency"}:
            if profile == "strict":
                return replace(decision, treatment="remove", category="cost")
            return (
                replace(decision, treatment="preserve", category="cost")
                if value in CURRENCIES
                else replace(decision, treatment="tokenise", category="free_text")
            )
        return replace(decision, treatment="preserve", category="safe_metadata") if decision is not None and self.is_literal(suffix, value) else decision

    def admitted_scan_container(self, value: object, suffix: str) -> bool:
        """Validate a scan-only strict timestamp view; preserve raw preflight and archive bytes."""
        return not self.unknown_paths(CommitmentScanAdmission.view(self, value, suffix), "", suffix)
