"""Closed actual-producer privacy contract for active-security-finding-review."""

from __future__ import annotations

from datetime import datetime
from math import isfinite
from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "findings": ("array", "safe_metadata", False),
    "findings[]": ("object", "safe_metadata", False),
    "findings[].provider": ("provider", "safe_metadata", False),
    "findings[].finding_id": ("string", "arn_or_name", False),
    "findings[].region": ("string", "region", False),
    "findings[].title": ("string", "resource_name", False),
    "findings[].severity": ("severity", "safe_metadata", True),
    "findings[].resource_type": ("string", "free_text", True),
    "findings[].resource_id": ("string", "arn_or_name", True),
    "findings[].description": ("string", "removed_diagnostic", True),
    "findings[].finding_type": ("string", "free_text", True),
    "findings[].workflow_status": ("workflow", "safe_metadata", True),
    "findings[].record_state": ("state", "safe_metadata", True),
    "findings[].updated_at": ("timestamp", "timestamp", True),
    "regions": ("array", "safe_metadata", False),
    "regions[]": ("string", "region", False),
    "warnings": ("array", "removed_diagnostic", False),
    "warnings[]": ("string", "removed_diagnostic", False),
    "collection_evidence_version": ("version", "safe_metadata", False),
}
VOCABULARIES = {
    "provider": ("GuardDuty", "Security Hub"),
    "workflow": ("active", "NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"),
    "state": ("active", "ACTIVE", "ARCHIVED"),
}


class SecurityFindingsPrivacyContract(ClosedProducerContract):
    """Scope explicit fields and finite metadata to the matching AWS producer."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject schema/legacy identity conflicts before interpreting the payload."""
        if record.get("scanner_id") != "active-security-finding-review":
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {
                (f"{namespace}.scanners.security_finding.active.evidence", "ActiveSecurityFindingEvidence")
                for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            }
        ):
            message = "Security privacy contract requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "severity":
            if isinstance(value, int | float) and not isinstance(value, bool):
                try:
                    return isfinite(value)
                except OverflowError:
                    return False
            return isinstance(value, str) and value.casefold() in {"critical", "high", "medium", "low", "info", "informational", "notice"}
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)
