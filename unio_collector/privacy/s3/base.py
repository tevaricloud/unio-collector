"""Closed privacy contracts for four exact S3 producer identities."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.s3.fields import PUBLIC_LITERALS
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
from unio_collector.scanners.scanner.schema import admit_evidence_schema


class S3PrivacyContract(ClosedProducerContract):
    """Preflight every descendant before standard or strict transformations."""

    scanners: ClassVar[dict[str, tuple[str, str]]] = {}

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Keep provider, legacy type/module and schema identities fail closed."""
        scanner = record.get("scanner_id")
        if not isinstance(scanner, str) or scanner not in cls.scanners:
            return None
        module, evidence_type = cls.scanners[scanner]
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.s3.{module}", evidence_type) for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "S3 privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate optional times and the only declared dynamic string map."""
        if value is None:
            return nullable
        if kind == "tag_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Permit only string entries in the exact lifecycle tags field."""
        if suffix == "records[].tags" and suffix in self.fields:
            return [] if self._valid(value, "tag_map", nullable=False) else [member + PREFIX[1:] + "." + suffix]
        return super().unknown_paths(value, member, suffix)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Tokenise arbitrary text and identities, including nullable skip reasons."""
        if "records[].tags" in self.fields and path.startswith(PREFIX + ".records[].tags."):
            return PrivacyTreatmentDecision(
                treatment="tokenise",
                category="tag_value",
                canonicaliser_id=None,
                canonicaliser_version=None,
                fallback_allowed=False,
                decision_source="exact_json_path",
                reason="String-only values in the exact admitted S3 tags map.",
            )
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision

    def mapping_key_category(self, path: str) -> str | None:
        """Protect arbitrary tag keys as well as their values."""
        return "tag_value" if path == PREFIX + ".records[].tags" and "records[].tags" in self.fields else None

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve finite provider constants only at their explicit status positions."""
        decision = self.resolve(path, profile)
        suffix = path.removeprefix(PREFIX + ".")
        if decision is not None and suffix in self.fields and value in PUBLIC_LITERALS.get(suffix, set()):
            return replace(decision, treatment="preserve", category="safe_metadata")
        return decision
