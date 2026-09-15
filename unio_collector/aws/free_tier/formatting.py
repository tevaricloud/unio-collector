from __future__ import annotations  # noqa: D100

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from unio_collector.core.optional_values import optional_string


def calculate_percentage(  # noqa: D103
    numerator: Decimal | None,
    denominator: Decimal | None,
) -> Decimal | None:
    if numerator is None or denominator is None or not numerator.is_finite() or not denominator.is_finite() or denominator == 0:
        return None
    return (numerator / denominator) * Decimal(100)


def parse_decimal(value: Any) -> Decimal | None:  # noqa: ANN401, D103
    if value in (None, ""):
        return None
    try:
        parsed = Decimal(str(value))
        return parsed if parsed.is_finite() else None
    except (InvalidOperation, ValueError):
        return None


def format_decimal_for_json(value: Decimal | None) -> str | None:  # noqa: D103
    if value is None or not value.is_finite():
        return None
    normalized = value.normalize()
    if normalized == normalized.to_integral_value():
        return str(normalized.quantize(Decimal(1)))
    return format(normalized, "f")


def format_date_for_json(value: Any) -> str | None:  # noqa: ANN401, D103
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if value in (None, ""):
        return None
    return str(value)


__all__ = [
    "calculate_percentage",
    "format_date_for_json",
    "format_decimal_for_json",
    "optional_string",
    "parse_decimal",
]
