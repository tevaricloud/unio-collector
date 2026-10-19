"""Exact registered neutral-pair flow producer and kind-specific topology admission."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.flow.fields import FIELDS
from unio_collector.privacy.flow.interface import FlowInterfaceContract
from unio_collector.privacy.flow.route import FlowRouteContract
from unio_collector.privacy.flow.topology_fields import FACT_PATHS

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


class FlowPrivacyContract(FlowPrivacyBase):
    """Preflight complete actual payloads before any strict omission or public scan view."""

    scanner_id: ClassVar[str] = "vpc-flow-log-attribution"
    identities: ClassVar = {scanner_id: ("network.vpc_flow.attribution.evidence", "VpcFlowLogAttributionEvidence", {})}
    fields: ClassVar = FIELDS

    @staticmethod
    def fact(value: dict[str, Any]) -> FlowPrivacyBase | None:
        """Use the source's structured kind, never prose or observed customer strings."""
        return FlowInterfaceContract() if value.get("kind") == "interface" else FlowRouteContract() if value.get("kind") == "route" else None

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject cross-kind fields, malformed tuple cells and incoherent period inputs."""
        if suffix in FACT_PATHS and isinstance(value, dict):
            contract = self.fact(value)
            return contract.unknown_paths(value, member, suffix) if contract is not None else [member + self.prefix[1:] + "." + suffix + ".kind"]
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "scan_period" and isinstance(value, dict):
            kind = value.get("kind")
            expected = {"date_from", "date_to"} if kind == "date_range" else {kind} if isinstance(kind, str) else set()
            if not isinstance(value.get("raw_input"), dict) or set(value["raw_input"]) != expected:
                failures.append(member + self.prefix[1:] + ".scan_period.raw_input")
        return failures

    def for_container(self, value: dict[str, Any], path: str) -> ClosedProducerContract | None:
        """Share the exact same structured fact routing in source transformation and scans."""
        return self.fact(value) if path.removeprefix(self.prefix + ".") in FACT_PATHS else None
