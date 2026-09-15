from __future__ import annotations  # noqa: D100

from datetime import UTC, date, datetime

from unio_collector.billing.period import CompletedMonthPeriod


class CompletedMonthPeriodResolver:
    """Resolve the immediately preceding complete UTC calendar month."""

    def resolve(self, *, reference_date: date | None = None) -> CompletedMonthPeriod:
        """Return the completed month preceding the supplied UTC date."""
        current = reference_date or datetime.now(UTC).date()
        end_exclusive = current.replace(day=1)
        previous_month_day = end_exclusive.replace(day=1) - date.resolution
        return CompletedMonthPeriod(
            start_date=previous_month_day.replace(day=1),
            end_date_exclusive=end_exclusive,
        )
