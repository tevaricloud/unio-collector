from __future__ import annotations  # noqa: D100

from collections.abc import Mapping
from datetime import date  # noqa: TC003
from typing import Any, cast

from pydantic import Field, model_validator

from unio_collector.core.base_model import UnioBaseModel
from unio_collector.core.scan.period import (
    PeriodKind,
    ScanPeriod,
)


class CollectorScanPeriodPayload(UnioBaseModel):
    """Serialized runtime scan period stored by collector-purpose bundles."""

    kind: PeriodKind
    raw_input: dict[str, Any]
    current_start_date: date
    current_end_date: date
    previous_start_date: date
    previous_end_date: date
    duration_days: int = Field(gt=0)
    selected_duration: str

    @model_validator(mode="after")
    def validate_period_boundaries(self) -> CollectorScanPeriodPayload:
        """Require internally consistent inclusive runtime period boundaries."""
        if self.current_end_date < self.current_start_date:
            msg = "Collector scan period current_end_date precedes current_start_date."
            raise ValueError(msg)
        if self.previous_end_date < self.previous_start_date:
            msg = "Collector scan period previous_end_date precedes previous_start_date."
            raise ValueError(msg)
        expected_duration = (self.current_end_date - self.current_start_date).days + 1
        if self.duration_days != expected_duration:
            msg = "Collector scan period duration_days does not match its inclusive current date range."
            raise ValueError(msg)
        return self

    def to_scan_period(self) -> ScanPeriod:
        """Return the exact runtime period represented by this payload."""
        return ScanPeriod(
            kind=self.kind,
            raw_input=dict(self.raw_input),
            current_start_date=self.current_start_date,
            current_end_date=self.current_end_date,
            previous_start_date=self.previous_start_date,
            previous_end_date=self.previous_end_date,
        )


def serialize_scan_period(period: object) -> dict[str, Any]:
    """Return the canonical scan-period payload for collector bundle metadata."""
    if hasattr(period, "convert_to_dict"):
        payload = cast("Any", period).convert_to_dict()
    elif hasattr(period, "model_dump"):
        payload = cast("Any", period).model_dump(mode="json")
    elif isinstance(period, Mapping):
        payload = dict(period)
    else:
        msg = f"Unsupported scan_period object for evidence bundle serialization: {type(period).__name__}"
        raise TypeError(msg)
    if not isinstance(payload, dict):
        msg = f"Scan period serializer returned unsupported payload type: {type(payload).__name__}"
        raise TypeError(msg)
    return payload
