"""Exact VPC endpoint topology and historical record privacy treatment."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.facts import enum_values
from unio_collector.privacy.network.vpc_fields import CLASSIFICATIONS, FIELDS, MAPS, SERVICE_LABELS

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class VpcEndpointPrivacyContract(NetworkPrivacyContract):
    """Keep dynamic keys confined to their declared typed identity/tag maps."""

    collection_names: ClassVar[frozenset[str]] = frozenset({"vpcs", "route_tables", "vpc_endpoints", "nat_gateways", "network_interfaces", "subnets"})
    scanner_id: ClassVar[str] = "network-vpc-endpoint-opportunity-review"
    evidence_module: ClassVar[str] = "scanners.network.vpc_endpoint.evidence"
    evidence_type: ClassVar[str] = "VpcEndpointOpportunityEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "string_map":
            return isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
        if kind in {"classification", "service_label", "interface_type", "true_string"}:
            values = (
                CLASSIFICATIONS
                if kind == "classification"
                else SERVICE_LABELS
                if kind == "service_label"
                else {"true"}
                if kind == "true_string"
                else enum_values("NetworkInterfaceType")
            )
            return isinstance(value, str) and value in values
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Preflight every dynamic container before any profile removes its contents."""
        if suffix in MAPS:
            return [] if self._valid(value, "string_map", nullable=False) else [member + PREFIX[1:] + "." + suffix]
        return super().unknown_paths(value, member, suffix)

    def mapping_key_category(self, path: str) -> str | None:
        """Protect customer keys only at the three exact typed-map positions."""
        return MAPS.get(path.removeprefix(PREFIX + ".")) if path.startswith(PREFIX + ".") else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve identity relationships for gateway keys and reserved tag-record IDs."""
        for suffix in MAPS:
            prefix = PREFIX + "." + suffix + "."
            if path.startswith(prefix):
                decision = super().resolve(PREFIX + "." + suffix, profile)
                if decision is None:
                    return None
                category = (
                    "region"
                    if suffix.endswith("availability_zones")
                    else "resource_id"
                    if suffix.endswith("nat_gateway_tags[]") and path == prefix + "nat_gateway_id"
                    else "tag_value"
                )
                return replace(
                    decision,
                    category=category,
                    treatment="generalise" if category == "region" and profile == "strict" else "preserve" if category == "region" else "tokenise",
                )
        return super().resolve(path, profile)
