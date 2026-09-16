from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.network.vpc_flow.query_options import VpcFlowQueryOptions

if TYPE_CHECKING:
    from unio_collector.aws.flow.observation import FlowObservation
    from unio_collector.core.scan.period import ScanPeriod


@dataclass(frozen=True)
class VpcFlowLogAttributionEvidence:  # noqa: D101
    collector: None = None
    records: list[FlowObservation] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    query_options: VpcFlowQueryOptions = field(default_factory=VpcFlowQueryOptions)
    regions: list[str] = field(default_factory=list)
    scan_period: ScanPeriod | None = None
