from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.service.usage.precheck import (
        ServiceUsagePrecheckDecision,
        ServiceUsagePrecheckPolicy,
    )
    from unio_collector.scanners.execution import (
        ScannerSchedulePlan,
        ScannerScheduleStageResult,
    )


@dataclass
class ScannerRunnerScheduleState:
    """Mutable scheduler and service-usage-precheck state."""

    service_usage_precheck_policy: ServiceUsagePrecheckPolicy
    scheduler_plan: ScannerSchedulePlan | None = None
    scheduler_stage_results: list[ScannerScheduleStageResult] = field(
        default_factory=list,
    )
    service_usage_precheck_decisions: list[ServiceUsagePrecheckDecision] = field(
        default_factory=list,
    )
