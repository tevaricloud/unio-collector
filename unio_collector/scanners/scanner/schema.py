"""Stable wire identities and import-free admission for bounded evidence families."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from unio_collector.collector.protocol import UNIO_PROTOCOL

if TYPE_CHECKING:
    from collections.abc import Mapping

BEDROCK_SCANNER_ID = "bedrock-cost-review"
BEDROCK_SCHEMA_ID = "aws.bedrock.cost-review"
BEDROCK_SCHEMA_VERSION = 1
LOG_RETENTION_SCANNER_ID = "cloudwatch-log-groups-without-retention"
LOG_RETENTION_SCHEMA_ID = "aws.cloudwatch.log-retention"


@dataclass(frozen=True)
class ScannerEvidenceSchema:
    """One frozen data identity, independent of application decoder locations."""

    scanner_id: str
    schema_id: str
    module_suffix: str
    type_name: str
    version: int = 1

    def validate(self, record: Mapping[str, object]) -> None:
        """Reject conflicting identity and unsupported v1 shape before imports."""
        if record.get("scanner_id") != self.scanner_id or ("provider_id" in record and record["provider_id"] != "aws"):
            msg = "Scanner evidence schema does not match its scanner or provider."
            raise ValueError(msg)
        if "evidence_module" in record or "evidence_type" in record:
            identities = tuple((f"{namespace}.{self.module_suffix}", self.type_name) for namespace in UNIO_PROTOCOL.accepted_import_namespaces)
            if (record.get("evidence_module"), record.get("evidence_type")) not in identities:
                msg = "Scanner evidence schema conflicts with legacy type metadata."
                raise ValueError(msg)
        value = record.get("payload")
        if not isinstance(value, dict) or set(value) != {"records", "regions"}:
            msg = "Scanner evidence schema v1 requires records and regions."
            raise ValueError(msg)
        records, regions = value["records"], value["regions"]
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            msg = "Scanner evidence schema v1 records must be a list of objects."
            raise ValueError(msg)
        if not isinstance(regions, list) or not all(isinstance(region, str) for region in regions):
            msg = "Scanner evidence schema v1 regions must be a list of strings."
            raise ValueError(msg)
        if self.scanner_id == LOG_RETENTION_SCANNER_ID:
            for item in records:
                if (
                    set(item) != {"log_group_name", "region", "stored_bytes"}
                    or not isinstance(item["log_group_name"], str)
                    or not isinstance(item["region"], str)
                    or (item["stored_bytes"] is not None and type(item["stored_bytes"]) is not int)
                ):
                    msg = "CloudWatch log-retention evidence schema v1 record is invalid."
                    raise ValueError(msg)


_SCHEMAS = MappingProxyType(
    {
        BEDROCK_SCHEMA_ID: ScannerEvidenceSchema(BEDROCK_SCANNER_ID, BEDROCK_SCHEMA_ID, "scanners.analytics_ai.bedrock.evidence", "BedrockCostReviewEvidence"),
        LOG_RETENTION_SCHEMA_ID: ScannerEvidenceSchema(
            LOG_RETENTION_SCANNER_ID, LOG_RETENTION_SCHEMA_ID, "scanners.cloudwatch.log_retention.evidence", "CloudWatchLogRetentionEvidence"
        ),
    }
)


def admit_evidence_schema(record: Mapping[str, object]) -> ScannerEvidenceSchema | None:
    """Admit a known v1 record or preserve the versionless compatibility path."""
    if "evidence_schema_id" not in record and "evidence_schema_version" not in record:
        return None
    schema_id, version = record.get("evidence_schema_id"), record.get("evidence_schema_version")
    if type(schema_id) is not str or not schema_id or type(version) is not int:
        msg = "Scanner evidence schema metadata is incomplete or invalid."
        raise ValueError(msg)
    schema = _SCHEMAS.get(schema_id)
    if schema is None or version != schema.version:
        msg = "Unsupported scanner evidence schema ID or version."
        raise ValueError(msg)
    schema.validate(record)
    return schema


def evidence_schema_metadata(scanner_id: str, evidence_type: type[object]) -> dict[str, object]:
    """Stamp only exact collection DTOs in the installed package namespace."""
    root = __name__.split(".", 1)[0]
    for schema in _SCHEMAS.values():
        if scanner_id == schema.scanner_id and (evidence_type.__module__, evidence_type.__name__) == (f"{root}.{schema.module_suffix}", schema.type_name):
            return {"evidence_schema_id": schema.schema_id, "evidence_schema_version": schema.version}
    return {}
