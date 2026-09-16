from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.network import PublicIpv4RegionRecord
    from unio_collector.aws.network.topology import NetworkTopologyEvidence


@dataclass(frozen=True)
class PublicIpv4Evidence:  # noqa: D101
    records: list[PublicIpv4RegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    network_evidence_version: str | None = None
    topology: list[NetworkTopologyEvidence] = field(default_factory=list)
