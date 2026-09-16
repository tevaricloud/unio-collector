"""Metric samples and factual read completeness with list-compatible counts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.metric.datapoint import MetricDatapoint
    from unio_collector.aws.metric.read.reason import MetricReadReason


class MetricReadValues(list["Decimal | MetricDatapoint"]):
    """Keep existing collection telemetry counts alongside provider completeness."""

    def __init__(
        self,
        values: list[Decimal | MetricDatapoint],
        *,
        status: Literal["complete", "partial", "unavailable"] = "complete",
        reason: MetricReadReason | None = None,
    ) -> None:
        """Retain whole samples without turning partial reads into complete means."""
        super().__init__(values)
        self.status = status
        self.reason = reason
