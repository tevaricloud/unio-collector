"""Independent aggregate admission for known-original metric scan normalization."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

from unio_collector.privacy.leak.public.temporal import MONTH_PRECISION_LENGTH, TemporalScanPolicy

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


def admitted_metric(value: object, contract: ClosedProducerContract, suffix: str) -> bool:
    """Retain complete typed/aggregate checks, including strict month precision.

    Only a temporary validation copy pads declared temporal leaves. Archive bytes,
    scanner return values, unknown members and arbitrary customer text are unchanged.
    """
    if not isinstance(value, dict):
        return False
    checked = deepcopy(value)
    for key in ("start_time", "end_time"):
        checked[key] = _temporal(checked.get(key))
    points = checked.get("datapoints")
    if isinstance(points, list):
        for point in points:
            if isinstance(point, dict) and "timestamp" in point:
                point["timestamp"] = _temporal(point["timestamp"])
    return not contract.unknown_paths(checked, "", suffix)


def _temporal(value: object) -> object:
    if isinstance(value, str) and len(value) == MONTH_PRECISION_LENGTH and TemporalScanPolicy.timestamp(value):
        return value + "-01"
    return value
