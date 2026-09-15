from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.aws.xray import (
    XRayCostSignal,
    XRayRegionRecord,
)


@dataclass(frozen=True)
class XRayCostGovernanceEvidence:  # noqa: D101
    records: list[XRayRegionRecord] = field(default_factory=list)
    cost_signal: XRayCostSignal = field(default_factory=XRayCostSignal)
    regions: list[str] = field(default_factory=list)
