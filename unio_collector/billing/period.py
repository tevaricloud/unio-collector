from __future__ import annotations  # noqa: D100

from datetime import date

from pydantic import model_validator

from unio_collector.core.base_model import UnioBaseModel


class CompletedMonthPeriod(UnioBaseModel):
    """Inclusive-start, exclusive-end completed calendar-month interval."""

    start_date: date
    end_date_exclusive: date

    @model_validator(mode="after")
    def validate_calendar_month(self) -> CompletedMonthPeriod:
        """Require exactly one complete calendar month."""
        if self.start_date.day != 1 or self.end_date_exclusive.day != 1:
            msg = "Completed-month boundaries must both be the first day of a month."
            raise ValueError(msg)
        previous_day = self.end_date_exclusive - date.resolution
        expected_start = previous_day.replace(day=1)
        if self.start_date != expected_start:
            msg = "Completed-month start must immediately precede the exclusive end."
            raise ValueError(msg)
        return self
