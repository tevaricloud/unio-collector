"""Closed aggregate idle evidence using its exact constituent DTO contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.ec2.elastic_ip import ElasticIpPrivacyContract
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.ec2.volume import EbsVolumePrivacyContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

CONTRACTS = {
    "elastic_ips": ElasticIpPrivacyContract(),
    "ebs_volumes": EbsVolumePrivacyContract(),
    "stopped_instances": StoppedInstancePrivacyContract(),
    "nat_gateways": NatInventoryPrivacyContract(),
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    **{
        collection + name.removeprefix("records"): spec
        for collection, contract in CONTRACTS.items()
        for name, spec in contract.fields.items()
        if name == "records" or name.startswith("records[]")
    },
}


class IdleBundlePrivacyContract(ClosedProducerContract):
    """Admit only this aggregate producer; keep each nested DTO's existing treatments."""

    scanner_id: ClassVar[str] = "idle-zombie-resource-detector"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Check immutable wire/import identity without importing a decoder."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        identities = {
            (namespace + ".scanners.ec2.inventory.evidence_bundle", "Ec2InventoryEvidenceBundle") for namespace in UNIO_PROTOCOL.accepted_import_namespaces
        }
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
        ):
            message = "Idle aggregate privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Delegate complete typed collections, preserving original diagnostic paths."""
        for collection, contract in CONTRACTS.items():
            if suffix == collection or suffix.startswith((collection + "[]", collection + ".")):
                relative = "records" + suffix.removeprefix(collection)
                failures = contract.unknown_paths(value, member, relative)
                return [failure.replace(PREFIX[1:] + ".records", PREFIX[1:] + "." + collection, 1) for failure in failures]
        return super().unknown_paths(value, member, suffix)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Use exact constituent schemas for nested fields and dynamic tag values."""
        suffix = path.removeprefix(PREFIX + ".")
        for collection, contract in CONTRACTS.items():
            if suffix == collection or suffix.startswith((collection + "[]", collection + ".")):
                return contract.resolve(PREFIX + ".records" + suffix.removeprefix(collection), profile)
        return super().resolve(path, profile)
