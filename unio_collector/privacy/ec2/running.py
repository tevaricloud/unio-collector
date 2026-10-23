"""Identity-bound running EC2 inventory, factual metrics and shutdown metadata."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.ec2.base import COMMON_FIELDS
from unio_collector.privacy.ec2.elastic_ip import ElasticIpPrivacyContract
from unio_collector.privacy.ec2.nat_inventory import FIELDS as NAT_FIELDS
from unio_collector.privacy.ec2.nat_inventory import VOCABULARIES as NAT_VOCABULARIES
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.ec2.schedule import FIELDS as SCHEDULE_FIELDS
from unio_collector.privacy.ec2.schedule import SCHEDULE, ShutdownPrivacySchema
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

VOCABULARIES = {
    "namespace": {"AWS/EC2"},
    "metric_name": {"CPUUtilization", "NetworkIn", "NetworkOut", "DiskReadOps", "DiskWriteOps", "StatusCheckFailed"},
    "statistic": {"Average", "Maximum"},
    "root_device": {"ebs", "instance-store", "unknown"},
    "lifecycle": {"spot", "scheduled", "capacity-block", "on-demand", "unknown"},
    "tenancy": {"default", "dedicated", "host"},
    "workload": {"autoscaling", "ecs", "eks", "emr"},
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    **{name: spec for name, spec in NAT_FIELDS.items() if name.startswith("records[].metric_summaries")},
    "records[].instance_id": ("string", "resource_id", False),
    "records[].instance_type": ("instance_type", "safe_metadata", False),
    "records[].launch_time": ("timestamp", "timestamp", True),
    "records[].root_device_type": ("root_device", "safe_metadata", False),
    "records[].instance_lifecycle": ("lifecycle", "safe_metadata", False),
    "records[].platform_details": ("string", "free_text", False),
    "records[].tenancy": ("tenancy", "safe_metadata", False),
    "records[].vpc_id": ("string", "resource_id", True),
    "records[].subnet_id": ("string", "resource_id", True),
    "records[].public_ip_address": ("ipv4", "ipv4", True),
    "records[].managed_workload_markers": ("array", "safe_metadata", False),
    "records[].managed_workload_markers[]": ("workload", "safe_metadata", False),
    **SCHEDULE_FIELDS,
}


class RunningInstancePrivacyContract(NatInventoryPrivacyContract):
    """Reuse exact factual metric validation without sharing producer identities."""

    scanner_id: ClassVar[str] = "ec2-idle-instance-review"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    def __init__(self, schedule_ids: frozenset[str] = frozenset()) -> None:
        """Bind lookup normalization to this record only, never shared mutable state."""
        self.schedule_ids = schedule_ids

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require the actual wrapper's exact AWS inventory envelope before imports."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        identities = {(namespace + ".scanners.inventory_evidence", "InventoryEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
        ):
            message = "Running EC2 privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        payload = record.get("payload")
        metadata = payload.get("metadata") if isinstance(payload, dict) else None
        schedule = metadata.get("scheduled_shutdown") if isinstance(metadata, dict) else None
        schedules = schedule.get("schedules") if isinstance(schedule, dict) else None
        return cls(frozenset(key for key in schedules if isinstance(key, str)) if isinstance(schedules, dict) else frozenset())

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Keep EC2 vocabularies distinct from the reused NAT metric schema."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "ipv4":
            return ElasticIpPrivacyContract._valid(value, kind, nullable=nullable)  # noqa: SLF001
        if kind == "context":
            return type(value) is int and value == MetricCollectionContext.EC2_INSTANCE
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Preflight nested schedule metadata before profile omission or tokenisation."""
        if suffix == SCHEDULE:
            return ShutdownPrivacySchema.validate(value, member)
        return super().unknown_paths(value, member, suffix)

    def mapping_key_category(self, path: str) -> str | None:
        """Protect IDs only at the declared schedule map, never arbitrary containers."""
        return "resource_id" if path == PREFIX + "." + SCHEDULE + ".schedules" else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect configuration text and platform strings, retaining typed observations."""
        canonical = PREFIX + "." + ShutdownPrivacySchema.canonical(path.removeprefix(PREFIX + "."), self.schedule_ids)
        decision = ClosedProducerContract.resolve(self, canonical, profile) if path.startswith(PREFIX + "." + SCHEDULE) else super().resolve(path, profile)
        if decision is not None and decision.category in {"free_text", "ipv4"}:
            return replace(decision, treatment="tokenise")
        return decision

    def is_public_literal(self, suffix: str, value: object) -> bool:
        """Recognize only finite constants at this exact identity-bound metadata position."""
        suffix = ShutdownPrivacySchema.canonical(suffix, self.schedule_ids)
        spec = self.fields.get(suffix)
        if spec is None or spec[1] != "safe_metadata" or not isinstance(value, str):
            return False
        kind = spec[0]
        if kind in VOCABULARIES or kind in NAT_VOCABULARIES:
            return value in VOCABULARIES.get(kind, NAT_VOCABULARIES.get(kind, set()))
        if kind == "instance_type":
            return self._valid(value, kind, nullable=False)
        return kind == "day" and ShutdownPrivacySchema._valid(value, kind, suffix)  # noqa: SLF001
