from __future__ import annotations  # noqa: D100

from datetime import date, timedelta


def parse_iso_date(value: str, option_name: str) -> date:  # noqa: D103
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        msg = f"{option_name} must be an ISO date in YYYY-MM-DD format."
        raise ValueError(
            msg,
        ) from exc


def subtract_months(value: date, months: int) -> date:  # noqa: D103
    month_index = value.year * 12 + value.month - 1 - months
    year = month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, days_in_month(year, month))
    return date(year, month, day)


def days_in_month(year: int, month: int) -> int:  # noqa: D103
    next_month = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)  # noqa: PLR2004
    return (next_month - timedelta(days=1)).day
