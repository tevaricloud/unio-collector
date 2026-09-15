from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from decimal import Decimal

from unio_collector.aws.cost_explorer.result import CostExplorerResult  # noqa: TC001


@dataclass(frozen=True)
class CostExplorerServiceDeltaEvidence:  # noqa: D101
    result: CostExplorerResult
    absolute_threshold: Decimal = Decimal(0)
    percent_threshold: Decimal = Decimal(0)
    analysis_inputs_version: int = 0
    absolute_threshold_supplied: bool = True
    percent_threshold_supplied: bool = True

    @classmethod
    def capture(cls, result: CostExplorerResult, config: object) -> CostExplorerServiceDeltaEvidence:
        """Record explicit inputs or their absence without supplying analysis policy."""
        deferred = getattr(config, "analysis_defaults_deferred", False) is True
        absolute = getattr(config, "absolute_threshold", Decimal(0))
        percent = getattr(config, "percent_threshold", Decimal(0))
        return cls(
            result=result,
            absolute_threshold=Decimal(str(absolute)) if absolute is not None else Decimal(0),
            percent_threshold=Decimal(str(percent)) if percent is not None else Decimal(0),
            analysis_inputs_version=1 if deferred else 0,
            absolute_threshold_supplied=not deferred or absolute is not None,
            percent_threshold_supplied=not deferred or percent is not None,
        )
