"""Closed privacy contract for actual unassociated Elastic IP evidence."""

from __future__ import annotations

from dataclasses import replace
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

DOMAINS = frozenset({"standard", "vpc"})
FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "records[].allocation_id": ("string", "resource_id", True),
    "records[].public_ip": ("ipv4", "ipv4", True),
    "records[].domain": ("address_domain", "safe_metadata", True),
}


class ElasticIpPrivacyContract(Ec2PrivacyContract):
    """Preflight every container and retain finite network-domain semantics."""

    scanner_id: ClassVar[str] = "ec2-unassociated-elastic-ips"
    fixture_type: ClassVar[str] = "ElasticIpFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Reject malformed address observations and unknown provider domains."""
        if value is None:
            return nullable
        if kind == "address_domain":
            return isinstance(value, str) and value in DOMAINS
        if kind == "ipv4":
            if not isinstance(value, str):
                return False
            try:
                IPv4Address(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep the established IPv4 token category for the one address field."""
        decision = super().resolve(path, profile)
        if decision is not None and path == PREFIX + ".records[].public_ip":
            return replace(decision, treatment="tokenise")
        return decision
