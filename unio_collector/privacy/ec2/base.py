"""Shared exact identity, finite metadata and typed tag-map handling for EC2."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from typing import Any, ClassVar, Self

from botocore.loaders import Loader

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
from unio_collector.scanners.scanner.schema import admit_evidence_schema

COMMON_FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "metadata": ("object", "safe_metadata", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    "records[].tags": ("tag_map", "tag_value", False),
}
VOCABULARIES = {
    "volume_type": ("standard", "io1", "io2", "gp2", "sc1", "st1", "gp3", "unknown"),
    "volume_state": ("creating", "available", "in-use", "deleting", "deleted", "error", "unknown"),
}


@lru_cache(maxsize=1)
def _instance_types() -> frozenset[str]:
    """Read the installed SDK's finite EC2 vocabulary offline, without a session."""
    values = Loader().load_service_model("ec2", "service-2")["shapes"]["InstanceType"]["enum"]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        message = "The installed EC2 instance-type vocabulary is malformed."
        raise ValueError(message)
    return frozenset(values) | {"unknown"}


class Ec2PrivacyContract(ClosedProducerContract):
    """Keep each concrete scanner schema separate and preserve exact legacy aliases."""

    scanner_id: ClassVar[str]
    fixture_type: ClassVar[str]

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Accept only exact current or registered historical AWS identities."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        schema = admit_evidence_schema(record)
        identities = {
            (f"{namespace}.scanners.{module}", evidence_type)
            for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            for module, evidence_type in (("inventory_evidence", "InventoryEvidence"), ("fixture_parity.synthetic_types", cls.fixture_type))
        }
        if schema is not None or record.get("provider_id", "aws") != "aws" or (record.get("evidence_module"), record.get("evidence_type")) not in identities:
            message = "EC2 privacy contract requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate provider metadata, nullable dates and the existing string tag map."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "instance_type":
            return isinstance(value, str) and value in _instance_types()
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
        """Only this declared tags container admits arbitrary string keys and values."""
        if suffix == "records[].tags":
            return [] if self._valid(value, "tag_map", nullable=False) else [member + PREFIX[1:] + "." + suffix]
        return super().unknown_paths(value, member, suffix)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect leaves only beneath the exact preflight-validated tag map."""
        prefix = PREFIX + ".records[].tags."
        if path.startswith(prefix) and path != prefix:
            return PrivacyTreatmentDecision(
                treatment="tokenise",
                category="tag_value",
                canonicaliser_id=None,
                canonicaliser_version=None,
                fallback_allowed=False,
                decision_source="exact_json_path",
                reason="String-only tag value in the exact recognized EC2 tags container.",
            )
        return super().resolve(path, profile)
