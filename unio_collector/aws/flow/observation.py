"""Neutral bounded flow aggregates, including passive historical evidence fields."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

FLOW_EVIDENCE_VERSION = "neutral-pairs-v1"


@dataclass(frozen=True)
class FlowObservation:
    """Observed pair totals; absent source fields are never synthesized."""

    region: str
    flow_log_id: str
    log_group_name: str
    resource_id: str | None
    srcaddr: str
    dstaddr: str
    action: str
    bytes: int
    packets: int
    flows: int
    traffic_classification: str | None = None
    src_eni_id: str | None = None
    src_resource_owner_id: str | None = None
    src_vpc_id: str | None = None
    src_subnet_id: str | None = None
    src_availability_zone: str | None = None
    src_description: str | None = None
    src_interface_type: str | None = None
    src_attachment_instance_id: str | None = None
    src_private_dns_name: str | None = None
    src_attribution_tags: dict[str, str] | None = None
    dst_eni_id: str | None = None
    dst_resource_owner_id: str | None = None
    dst_vpc_id: str | None = None
    dst_subnet_id: str | None = None
    dst_availability_zone: str | None = None
    dst_description: str | None = None
    dst_interface_type: str | None = None
    dst_attachment_instance_id: str | None = None
    dst_private_dns_name: str | None = None
    dst_attribution_tags: dict[str, str] | None = None
    src_route_table_id: str | None = None
    src_default_route_target: str | None = None
    src_default_route_target_type: str | None = None
    src_route_table_association: str | None = None
    dst_route_table_id: str | None = None
    dst_default_route_target: str | None = None
    dst_default_route_target_type: str | None = None
    dst_route_table_association: str | None = None

    src_address_status: str = "not_attempted"
    dst_address_status: str = "not_attempted"

    def convert_to_dict(self) -> dict[str, Any]:
        """Copy evidence without interpreting traffic or topology."""
        return asdict(self)
