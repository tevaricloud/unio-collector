"""Closed current and legacy CloudWatch log-retention producer privacy."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.scanners.scanner.schema import LOG_RETENTION_SCANNER_ID, LOG_RETENTION_SCHEMA_ID, admit_evidence_schema

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "records[].log_group_name": ("string", "resource_name", False),
    "records[].region": ("string", "region", False),
    "records[].stored_bytes": ("count", "safe_metadata", True),
}


class LogRetentionPrivacyContract(ClosedProducerContract):
    """Reject every unknown child, including nulls, before fallback treatment."""

    scanner_id: ClassVar[str] = LOG_RETENTION_SCANNER_ID
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind only the registered AWS schema or exact historical DTO identity."""
        if record.get("scanner_id") != LOG_RETENTION_SCANNER_ID:
            return None
        schema = admit_evidence_schema(record)
        identities = {
            (f"{namespace}.scanners.{module}", kind)
            for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            for module, kind in (
                ("cloudwatch.log_retention.evidence", "CloudWatchLogRetentionEvidence"),
                ("fixture_parity.synthetic_types", "CloudWatchLogRetentionFixtureEvidence"),
            )
        }
        if record.get("provider_id", "aws") != "aws" or (
            (schema is None and (record.get("evidence_module"), record.get("evidence_type")) not in identities)
            or (schema is not None and (schema.schema_id, schema.version) != (LOG_RETENTION_SCHEMA_ID, 1))
        ):
            message = "Log-retention privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require record members while preserving defaulted legacy root lists."""
        failures = super().unknown_paths(value, member, suffix)
        if isinstance(value, dict) and suffix == "records[]":
            required = {"log_group_name", "region", "stored_bytes"}
            prefix = member + PREFIX[1:] + ("." + suffix if suffix else "")
            failures.extend(prefix + "." + key for key in sorted(required - value.keys()))
        return failures
