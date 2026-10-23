"""Identity-bound admission and treatments for four audit-service producers."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.audit.condition import AuditConditionContract
from unio_collector.privacy.audit.fields import SCANNERS, VOCABULARIES
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class AuditPrivacyContract(ClosedProducerContract):
    """Reject unknown descendants before strict omission of declared financial values."""

    identities: ClassVar = SCANNERS
    scanner_id: ClassVar[str]

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require matching scanner, provider and registered legacy DTO identity."""
        scanner = record.get("scanner_id")
        if not isinstance(scanner, str) or scanner != cls.scanner_id:
            return None
        module, evidence_type, _ = cls.identities[scanner]
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.{module}", evidence_type) for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Audit privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate explicit vocabularies and ISO timestamps without provider imports."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def for_container(self, value: dict[str, Any], path: str) -> ClosedProducerContract | None:
        """Use declared selector field meaning, not string values, to route treatments."""
        suffix = path.removeprefix("$.scanner_evidence[].payload.")
        if suffix in self.fields and suffix.endswith(".field_conditions[]"):
            return AuditConditionContract(str(value.get("field", "")))
        return None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Tokenise arbitrary diagnostics, selector expressions and metadata names."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision
