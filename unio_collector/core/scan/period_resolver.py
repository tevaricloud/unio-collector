from __future__ import annotations  # noqa: D100

from datetime import UTC, date, datetime, timedelta
from typing import Any

from unio_collector.core.period_helpers import parse_iso_date, subtract_months
from unio_collector.core.scan.period import PeriodKind, ScanPeriod


class ScanPeriodResolver:
    """Resolve CLI/config period options into current and previous windows."""

    def resolve(  # noqa: D102
        self,
        *,
        days: int | None = None,
        months: int | None = None,
        years: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        reference_date: date | None = None,
    ) -> ScanPeriod:
        self._validate_period_options(
            days=days,
            months=months,
            years=years,
            date_from=date_from,
            date_to=date_to,
        )
        today = reference_date or datetime.now(UTC).date()
        if date_from or date_to:
            return self._resolve_date_range(date_from=date_from, date_to=date_to)
        if months is not None:
            return self._resolve_relative_months(months, today)
        if years is not None:
            return self._resolve_relative_years(years, today)
        return self._resolve_relative_days(days or 14, today)

    def _validate_period_options(
        self,
        *,
        days: int | None,
        months: int | None,
        years: int | None,
        date_from: str | None,
        date_to: str | None,
    ) -> None:
        relative_options = [name for name, value in (("days", days), ("months", months), ("years", years)) if value is not None]
        if len(relative_options) > 1:
            joined = ", ".join(f"--{name}" for name in relative_options)
            msg = f"Only one relative scan period can be used per scan: {joined}."
            raise ValueError(
                msg,
            )
        if (date_from is None) != (date_to is None):
            msg = "--date-from and --date-to must be used together."
            raise ValueError(msg)
        if date_from is not None and relative_options:
            msg = "Explicit date ranges cannot be combined with --days, --months, or --years."
            raise ValueError(
                msg,
            )
        for name, value in (("days", days), ("months", months), ("years", years)):
            if value is not None and value <= 0:
                msg = f"--{name} must be greater than zero."
                raise ValueError(msg)

    def _resolve_date_range(
        self,
        *,
        date_from: str | None,
        date_to: str | None,
    ) -> ScanPeriod:
        if date_from is None or date_to is None:
            msg = "--date-from and --date-to must be used together."
            raise ValueError(msg)
        start = parse_iso_date(date_from, "--date-from")
        end = parse_iso_date(date_to, "--date-to")
        if end < start:
            msg = "--date-to must be on or after --date-from."
            raise ValueError(msg)
        duration = (end - start).days + 1
        previous_end = start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=duration - 1)
        return ScanPeriod(
            kind="date_range",
            raw_input={"date_from": date_from, "date_to": date_to},
            current_start_date=start,
            current_end_date=end,
            previous_start_date=previous_start,
            previous_end_date=previous_end,
        )

    def _resolve_relative_days(self, days: int, today: date) -> ScanPeriod:
        current_end = today - timedelta(days=1)
        current_start = current_end - timedelta(days=days - 1)
        previous_end = current_start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=days - 1)
        return ScanPeriod(
            kind="days",
            raw_input={"days": days},
            current_start_date=current_start,
            current_end_date=current_end,
            previous_start_date=previous_start,
            previous_end_date=previous_end,
        )

    def _resolve_relative_months(self, months: int, today: date) -> ScanPeriod:
        current_end = today - timedelta(days=1)
        current_start = subtract_months(current_end + timedelta(days=1), months)
        return self._build_relative_period(
            kind="months",
            raw_input={"months": months},
            current_start=current_start,
            current_end=current_end,
        )

    def _resolve_relative_years(self, years: int, today: date) -> ScanPeriod:
        current_end = today - timedelta(days=1)
        current_start = subtract_months(current_end + timedelta(days=1), years * 12)
        return self._build_relative_period(
            kind="years",
            raw_input={"years": years},
            current_start=current_start,
            current_end=current_end,
        )

    def _build_relative_period(
        self,
        *,
        kind: PeriodKind,
        raw_input: dict[str, Any],
        current_start: date,
        current_end: date,
    ) -> ScanPeriod:
        duration = (current_end - current_start).days + 1
        previous_end = current_start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=duration - 1)
        return ScanPeriod(
            kind=kind,
            raw_input=raw_input,
            current_start_date=current_start,
            current_end_date=current_end,
            previous_start_date=previous_start,
            previous_end_date=previous_end,
        )
