from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

PeriodKind = Literal["days", "months", "years", "date_range"]


@dataclass(frozen=True)
class ScanPeriod:  # noqa: D101
    kind: PeriodKind
    raw_input: dict[str, Any]
    current_start_date: date
    current_end_date: date
    previous_start_date: date
    previous_end_date: date

    @property
    def duration_days(self) -> int:  # noqa: D102
        return (self.current_end_date - self.current_start_date).days + 1

    @property
    def current_end_exclusive(self) -> date:  # noqa: D102
        return self.current_end_date + timedelta(days=1)

    @property
    def previous_end_exclusive(self) -> date:  # noqa: D102
        return self.previous_end_date + timedelta(days=1)

    @property
    def current_start_datetime(self) -> datetime:  # noqa: D102
        return datetime.combine(
            self.current_start_date,
            datetime.min.time(),
            tzinfo=UTC,
        )

    @property
    def current_end_exclusive_datetime(self) -> datetime:  # noqa: D102
        return datetime.combine(
            self.current_end_exclusive,
            datetime.min.time(),
            tzinfo=UTC,
        )

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "kind": self.kind,
            "raw_input": self.raw_input,
            "current_start_date": self.current_start_date.isoformat(),
            "current_end_date": self.current_end_date.isoformat(),
            "previous_start_date": self.previous_start_date.isoformat(),
            "previous_end_date": self.previous_end_date.isoformat(),
            "duration_days": self.duration_days,
            "selected_duration": self.describe_selected_duration(),
        }

    def describe_selected_duration(self) -> str:  # noqa: D102
        if "days" in self.raw_input:
            amount = self.raw_input["days"]
            return f"{amount} day{'s' if amount != 1 else ''}"
        if "months" in self.raw_input:
            amount = self.raw_input["months"]
            return f"{amount} month{'s' if amount != 1 else ''}"
        if "years" in self.raw_input:
            amount = self.raw_input["years"]
            return f"{amount} year{'s' if amount != 1 else ''}"
        if "date_from" in self.raw_input and "date_to" in self.raw_input:
            return "explicit date range"
        return "not recorded"
