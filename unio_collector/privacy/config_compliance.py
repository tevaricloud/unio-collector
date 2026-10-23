"""Closed actual-producer privacy contract for aws-config-compliance-review."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "records[].region": ("string", "region", False),
    "records[].rule_name": ("string", "resource_name", False),
    "records[].compliance_type": ("compliance", "safe_metadata", False),
    "records[].annotation": ("string", "removed_diagnostic", True),
    "conformance_pack_records": ("array", "safe_metadata", False),
    "conformance_pack_records[]": ("object", "safe_metadata", False),
    "conformance_pack_records[].region": ("string", "region", False),
    "conformance_pack_records[].ConfigRuleName": ("string", "resource_name", False),
    "conformance_pack_records[].ConformancePackName": ("string", "resource_name", False),
    "conformance_pack_records[].ComplianceType": ("pack_compliance", "safe_metadata", False),
    "conformance_pack_records[].Controls": ("array", "safe_metadata", False),
    "conformance_pack_records[].Controls[]": ("string", "resource_name", False),
    "regions": ("array", "safe_metadata", False),
    "regions[]": ("string", "region", False),
    "warnings": ("array", "removed_diagnostic", False),
    "warnings[]": ("string", "removed_diagnostic", False),
}
VOCABULARIES = {
    "compliance": ("COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"),
    "pack_compliance": ("COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA"),
}


class ConfigCompliancePrivacyContract(ClosedProducerContract):
    """Scope explicit fields and finite metadata to the matching AWS producer."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject schema/legacy identity conflicts before interpreting the payload."""
        if record.get("scanner_id") != "aws-config-compliance-review":
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.config.compliance.evidence", "ConfigComplianceEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
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
        return super()._valid(value, kind, nullable=nullable)
