from __future__ import annotations  # noqa: D100

from unio_collector.core.base_model import UnioBaseModel


class ConsolidatedCoverageSummary(UnioBaseModel):
    """Persist organization account coverage without collapsing outcomes."""

    discovered: int
    selected: int
    excluded: int
    completed: int = 0
    degraded: int = 0
    failed: int = 0
    timed_out: int = 0
    cancelled: int = 0
