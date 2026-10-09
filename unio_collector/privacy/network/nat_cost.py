"""Exact NAT cost evidence, composing existing inventory and daily observation contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.daily_evidence import DailyEvidencePrivacyContract
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.fields import FIELDS as TOPOLOGY_FIELDS

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

DELEGATES = {"nat_gateways": NatInventoryPrivacyContract(), "daily_costs": DailyEvidencePrivacyContract()}
FIELDS = {
    **TOPOLOGY_FIELDS,
    **{
        key.replace("records", prefix, 1): value
        for prefix, contract in DELEGATES.items()
        for key, value in contract.fields.items()
        if key == "records" or key.startswith("records[")
    },
}


def _delegate(suffix: str) -> tuple[str, ClosedProducerContract, str] | None:
    for prefix, contract in DELEGATES.items():
        if suffix == prefix or suffix.startswith((prefix + "[", prefix + ".")):
            return prefix, contract, "records" + suffix[len(prefix) :]
    return None


class NatCostPrivacyContract(NetworkPrivacyContract):
    """Keep DTO semantics consistent without admitting arbitrary nested maps."""

    collection_names: ClassVar[frozenset[str]] = frozenset({"nat_gateways"})
    scanner_id: ClassVar[str] = "nat-gateway-cost-review"
    evidence_module: ClassVar[str] = "scanners.network.nat_gateway.evidence"
    evidence_type: ClassVar[str] = "NatGatewayCostEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reuse exact nested types, metrics consistency and finite-value validation."""
        delegate = _delegate(suffix)
        if delegate is not None:
            prefix, contract, translated = delegate
            return [path.replace(PREFIX[1:] + ".records", PREFIX[1:] + "." + prefix, 1) for path in contract.unknown_paths(value, member, translated)]
        return super().unknown_paths(value, member, suffix)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep whole diagnostic tokens, tag policy and strict financial removal."""
        delegate = _delegate(path.removeprefix(PREFIX + ".")) if path.startswith(PREFIX + ".") else None
        if delegate is not None:
            _, contract, translated = delegate
            return contract.resolve(PREFIX + "." + translated, profile)
        return super().resolve(path, profile)
