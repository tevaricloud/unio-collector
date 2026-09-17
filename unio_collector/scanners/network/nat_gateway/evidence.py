from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.aws.network.topology import NetworkTopologyEvidence


@dataclass(frozen=True)
class NatGatewayCostEvidence:  # noqa: D101
    nat_gateways: list[NatGatewayRecord] = field(default_factory=list)
    daily_costs: list[DailyCostRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["global"])
    network_evidence_version: str | None = None
    topology: list[NetworkTopologyEvidence] = field(default_factory=list)
