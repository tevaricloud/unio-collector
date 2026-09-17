from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from decimal import Decimal, DecimalException
from typing import TYPE_CHECKING, Any

from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.read.reason import MetricReadReason

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.metric.datapoint import MetricDatapoint


@dataclass(frozen=True)
class MetricSummary:  # noqa: D101
    namespace: str
    metric_name: str
    statistic: str
    period: int
    start_time: datetime
    end_time: datetime
    observed_min: Decimal | None
    observed_max: Decimal | None
    observed_average: Decimal | None
    threshold_used: Decimal | None
    interpretation: str
    limitation: str | None = None
    datapoints: tuple[MetricDatapoint, ...] = field(default_factory=tuple)
    collection_evidence_version: int = 0
    collection_context: int | None = None
    collection_status: str | None = None
    collection_reason: int | None = None
    observed_average_parts: tuple[int, tuple[int, ...], int] | None = None

    def __post_init__(self) -> None:
        """Reject unknown or internally inconsistent factual evidence formats."""
        version = self.collection_evidence_version
        if type(version) is not int or version not in {0, 1}:
            message = "Unsupported metric collection evidence version."
            raise ValueError(message)
        if version == 0:
            return
        if self.collection_context is not None and (
            not isinstance(self.collection_context, int)
            or isinstance(self.collection_context, bool)
            or self.collection_context not in set(MetricCollectionContext)
        ):
            message = "Unknown metric collection context."
            raise ValueError(message)
        if self.collection_status not in {"complete", "partial", "unavailable"}:
            message = "Metric collection completeness is missing or unknown."
            raise ValueError(message)
        if self.collection_reason is not None and (
            not isinstance(self.collection_reason, int) or isinstance(self.collection_reason, bool) or self.collection_reason not in set(MetricReadReason)
        ):
            message = "Metric collection reason code is unknown."
            raise ValueError(message)
        average = self._decode_average_parts()
        values = (self.observed_min, self.observed_max, self.observed_average, average)
        if any(value is not None and (not isinstance(value, Decimal) or not value.is_finite()) for value in values):
            message = "Metric observations must contain finite decimal aggregates."
            raise ValueError(message)
        if self.collection_status != "complete" and any(value is not None for value in values):
            message = "Incomplete metric evidence cannot supply complete aggregates."
            raise ValueError(message)
        if any((value is None) != (average is None) for value in values):
            message = "Metric evidence is missing its corresponding average."
            raise ValueError(message)
        self._validate_rounded_average(average)

    def _validate_rounded_average(self, average: Decimal | None) -> None:
        if average is None:
            return
        try:
            consistent = average.quantize(Decimal("0.01")) == self.observed_average
        except DecimalException:
            consistent = False
        if not consistent:
            message = "Metric rounded and exact averages are inconsistent."
            raise ValueError(message)

    def _decode_average_parts(self) -> Decimal | None:
        parts = self.observed_average_parts
        if parts is None:
            return None
        if not isinstance(parts, tuple) or len(parts) != 3:  # noqa: PLR2004
            message = "Metric average components are missing or malformed."
            raise ValueError(message)
        sign, digits, exponent = parts
        if type(sign) is not int or sign not in {0, 1} or type(exponent) is not int or not isinstance(digits, tuple) or not digits:
            message = "Metric average components are missing or malformed."
            raise ValueError(message)
        if any(type(digit) is not int or not 0 <= digit <= 9 for digit in digits):  # noqa: PLR2004
            message = "Metric average digits are malformed."
            raise ValueError(message)
        return Decimal(parts)

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        result = {
            "metric_name": self.metric_name,
            "namespace": self.namespace,
            "statistic": self.statistic,
            "period": self.period,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "observed_min": (str(self.observed_min) if self.observed_min is not None else None),
            "observed_max": (str(self.observed_max) if self.observed_max is not None else None),
            "observed_average": (str(self.observed_average) if self.observed_average is not None else None),
            "threshold_used": (str(self.threshold_used) if self.threshold_used is not None else None),
            "interpretation": self.interpretation,
            "limitation": self.limitation,
            "datapoint_count": len(self.datapoints),
            "datapoints": [point.convert_to_dict() for point in self.datapoints],
        }
        if self.collection_evidence_version != 0:
            result.update(
                collection_evidence_version=self.collection_evidence_version,
                collection_context=self.collection_context,
                collection_status=self.collection_status,
                collection_reason=self.collection_reason,
                observed_average_parts=self.observed_average_parts,
            )
        return result


__all__ = ["MetricSummary"]
