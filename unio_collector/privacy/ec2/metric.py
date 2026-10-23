"""Exact serialized metric validation for the load-balancer producer."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, DecimalException
from typing import Any

from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.summary import MetricSummary


class LoadBalancerMetricValidator:
    """Apply the current DTO consistency checks after closed-field preflight."""

    @staticmethod
    def valid_parts(value: object) -> bool:
        """Accept only the Decimal sign, nonempty digits and signed exponent tuple."""
        if not isinstance(value, list) or len(value) != 3:  # noqa: PLR2004
            return False
        sign, digits, exponent = value
        return (
            type(sign) is int
            and sign in {0, 1}
            and type(exponent) is int
            and isinstance(digits, list)
            and bool(digits)
            and all(type(digit) is int and 0 <= digit <= 9 for digit in digits)  # noqa: PLR2004
        )

    @staticmethod
    def validate(value: dict[str, Any]) -> bool:
        """Reject inconsistent current aggregates without discarding legacy evidence."""
        try:
            parts = value.get("observed_average_parts")
            decoded_parts = (parts[0], tuple(parts[1]), parts[2]) if parts is not None else None
            MetricSummary(
                namespace=value["namespace"],
                metric_name=value["metric_name"],
                statistic=value["statistic"],
                period=value["period"],
                start_time=datetime.fromisoformat(value["start_time"]),
                end_time=datetime.fromisoformat(value["end_time"]),
                observed_min=Decimal(str(value["observed_min"])) if value["observed_min"] is not None else None,
                observed_max=Decimal(str(value["observed_max"])) if value["observed_max"] is not None else None,
                observed_average=Decimal(str(value["observed_average"])) if value["observed_average"] is not None else None,
                threshold_used=Decimal(str(value["threshold_used"])) if value["threshold_used"] is not None else None,
                interpretation=value["interpretation"],
                limitation=value.get("limitation"),
                datapoints=tuple(
                    MetricDatapoint(datetime.fromisoformat(point["timestamp"]), Decimal(str(point["value"]))) for point in value.get("datapoints", [])
                ),
                collection_evidence_version=value.get("collection_evidence_version", 0),
                collection_context=value.get("collection_context"),
                collection_status=value.get("collection_status"),
                collection_reason=value.get("collection_reason"),
                observed_average_parts=decoded_parts,
            )
        except (KeyError, TypeError, ValueError, DecimalException, OverflowError):
            return False
        return True
