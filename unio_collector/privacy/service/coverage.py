"""Identity-bound privacy for Route53, SNS, Step Functions and Lightsail."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.service.fields import FIELDS, RESOURCE_ATTRIBUTES, SCANNERS, VOCABULARIES, Spec
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
from unio_collector.scanners.scanner.schema import admit_evidence_schema


class ServiceCoveragePrivacyContract(ClosedProducerContract):
    """Admit fields by scanner and record kind before any privacy omission."""

    fields: ClassVar[dict[str, Spec]] = FIELDS

    def __init__(self, scanner_id: str) -> None:
        """Bind the service, resource kinds and metadata to one known producer."""
        self.scanner_id = scanner_id

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject conflicting schema, provider and module identities before traversal."""
        scanner = record.get("scanner_id")
        if not isinstance(scanner, str) or scanner not in SCANNERS:
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.service.coverage.evidence", "ServiceCoverageEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Service coverage privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls(scanner)

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Keep enums, tags and optional producer timestamps explicitly typed."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "tag_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            if not value:
                return True
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject wrong-kind attributes and undeclared empty or null descendants."""
        path = member + PREFIX[1:] + ("." + suffix if suffix else "")
        if suffix == "records[].tags":
            return [] if self._valid(value, "tag_map", nullable=False) else [path]
        failures = super().unknown_paths(value, member, suffix)
        service, kinds, metadata = SCANNERS[self.scanner_id]
        if suffix == "metadata" and isinstance(value, dict):
            failures.extend(path + "." + key for key in value if key not in metadata)
        if suffix == "records[]" and isinstance(value, dict):
            if value.get("service") != service:
                failures.append(path + ".service")
            kind = value.get("resource_type")
            if not isinstance(kind, str) or kind not in kinds:
                failures.append(path + ".resource_type")
            elif isinstance(value.get("attributes"), dict):
                failures.extend(path + ".attributes." + key for key in value["attributes"] if key not in RESOURCE_ATTRIBUTES[kind])
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect arbitrary warning text and only the explicitly typed tag map."""
        if path.startswith(PREFIX + ".records[].tags."):
            return PrivacyTreatmentDecision(
                treatment="tokenise",
                category="tag_value",
                canonicaliser_id=None,
                canonicaliser_version=None,
                fallback_allowed=False,
                decision_source="exact_json_path",
                reason="String-only tags in the admitted service coverage record.",
            )
        decision = super().resolve(path, profile)
        if decision is not None and decision.category == "free_text":
            return replace(decision, treatment="tokenise")
        return decision

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve measurable counts, protect malformed observations and arbitrary states."""
        decision = self.resolve(path, profile)
        if decision is not None and path == PREFIX + ".records[].attributes.subscription_count":
            if value.isascii() and value.isdecimal():
                return replace(decision, treatment="preserve", category="safe_metadata")
            return replace(decision, treatment="tokenise", category="free_text")
        if decision is not None and path == PREFIX + ".records[].attributes.state" and value in {"running", "stopped"}:
            return replace(decision, treatment="preserve", category="safe_metadata")
        return decision
