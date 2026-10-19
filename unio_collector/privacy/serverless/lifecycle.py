"""Closed actual six-service lifecycle inventory with protected AMI and tag identities."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.leak.public.temporal import MONTH_PRECISION_LENGTH, TemporalScanPolicy
from unio_collector.privacy.s3.fields import fields
from unio_collector.privacy.serverless.lifecycle_literals import CONTROLS, public_engine, public_version
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

SCANNER = "extended-support-and-eol-review"
RECORD_KEYS = frozenset(
    {
        "service",
        "resource_id",
        "resource_name",
        "account_id",
        "region",
        "arn",
        "engine",
        "version",
        "tags",
        "platform",
        "resource_type",
        "evidence_source",
        "attributes",
    }
)


class LifecyclePrivacyContract(ClosedProducerContract):
    """Bind version semantics to the actual service while protecting all arbitrary text."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("records regions", "array"),
        **fields("records[] records[].attributes", "object"),
        **fields("metadata", "empty_object"),
        **fields("regions[] records[].region", "string", "region"),
        **fields("records[].service", "service"),
        **fields("records[].account_id", "string", "aws_account_id"),
        **fields("records[].resource_id", "string", "resource_id"),
        **fields("records[].arn", "string", "arn", nullable=True),
        **fields(
            "records[].resource_name records[].engine records[].version records[].platform records[].resource_type records[].evidence_source",
            "string",
            "resource_name",
            nullable=True,
        ),
        **fields("records[].tags", "tag_map", "tag_value"),
        **fields("records[].attributes.ami_id", "string", "resource_id", nullable=True),
        **fields("records[].attributes.ami_name", "string", "resource_name", nullable=True),
        **fields("records[].attributes.ami_creation_date", "timestamp", "timestamp", nullable=True),
        **fields("records[].attributes.instance_state", "string", "resource_name", nullable=True),
    }

    def __init__(self, service: str = "", engine: object = None) -> None:
        """Scope semantic public values to one independently validated record."""
        self.service, self.engine = service, engine

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require the exact registered legacy AWS inventory identity before inspecting values."""
        if record.get("scanner_id") != SCANNER:
            return None
        identities = {(namespace + ".scanners.inventory_evidence", "InventoryEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
        ):
            message = "Lifecycle privacy requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "service":
            return isinstance(value, str) and value in CONTROLS
        if kind == "empty_object":
            return value == {} and isinstance(value, dict)
        if kind == "tag_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except (ValueError, OverflowError):
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Validate complete records, exact AMI attributes and declared string-only tags."""
        path = member + PREFIX[1:] + "." + suffix
        if suffix == "records[].tags":
            return [] if self._valid(value, "tag_map", nullable=False) else [path]
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "records[]" and isinstance(value, dict):
            if not (RECORD_KEYS - {"platform", "resource_type", "evidence_source", "attributes"}).issubset(value) or not set(value).issubset(RECORD_KEYS):
                failures.append(path)
            service = value.get("service")
            if isinstance(service, str) and service in CONTROLS:
                resource_type, evidence_source = CONTROLS[service]
                if value.get("resource_type") not in (None, resource_type) or value.get("evidence_source") not in (None, evidence_source):
                    failures.append(path + ".producer_controls")
                required = {"ami_id", "ami_name", "ami_creation_date", "instance_state"} if service == "Amazon EC2" else set()
                attributes = value.get("attributes", {})
                if not isinstance(attributes, dict) or not set(attributes).issubset(required):
                    failures.append(path + ".attributes")
        return failures

    def admitted_scan_record(self, value: object) -> bool:
        """Validate strict temporal precision on a scan-only copy, preserving every archive byte."""
        if not isinstance(value, dict):
            return False
        checked = deepcopy(value)
        attributes = checked.get("attributes")
        if isinstance(attributes, dict):
            timestamp = attributes.get("ami_creation_date")
            if isinstance(timestamp, str) and len(timestamp) == MONTH_PRECISION_LENGTH and TemporalScanPolicy.timestamp(timestamp):
                attributes["ami_creation_date"] = timestamp + "-01"
        return not self.unknown_paths(checked, "", "records[]")

    def for_container(self, value: dict[str, Any], path: str) -> LifecyclePrivacyContract | None:
        """Bind exact record roles without carrying state between sibling records."""
        if not self.service and path == PREFIX + ".records[]" and isinstance(value.get("service"), str):
            return LifecyclePrivacyContract(value["service"], value.get("engine"))
        return None

    def mapping_key_category(self, path: str) -> str | None:
        """Protect arbitrary tag keys only in the declared typed tag container."""
        return "tag_key" if path == PREFIX + ".records[].tags" else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect all arbitrary tag values without adding dynamic field admission."""
        if path.startswith(PREFIX + ".records[].tags."):
            decision = super().resolve(PREFIX + ".records[].resource_id", profile)
            if decision is not None:
                return replace(decision, category="tag_value")
        return super().resolve(path, profile)

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve only public semantic controls and versions in their exact bound roles."""
        decision = self.resolve(path, profile)
        if decision is not None and self.service == "Amazon EC2" and path == PREFIX + ".records[].version":
            return replace(decision, treatment="tokenise", category="resource_id")
        return (
            replace(decision, treatment="preserve", category="safe_metadata")
            if decision is not None and self.is_literal(path.removeprefix(PREFIX + "."), value)
            else decision
        )

    def is_literal(self, suffix: str, value: object) -> bool:
        """Keep identifiers, unknown versions, arbitrary platforms and tag data scanned."""
        if suffix == "records[].service":
            return isinstance(value, str) and value in CONTROLS
        if not self.service or self.service not in CONTROLS:
            return False
        if suffix == "records[].engine":
            return public_engine(self.service, value)
        if suffix == "records[].version":
            return public_version(self.service, self.engine, value)
        controls = CONTROLS[self.service]
        if suffix == "records[].resource_type":
            return value == controls[0]
        if suffix == "records[].evidence_source":
            return value == controls[1]
        return suffix == "records[].platform" and (
            (self.service, value) in {("AWS Lambda", "Lambda runtime"), ("Amazon OpenSearch Service", "OpenSearch"), ("Amazon EKS", "Kubernetes")}
            or (self.service == "Amazon ElastiCache" and public_engine(self.service, value))
        )
