"""Scalar admission for exact provider fields, never permissive leaf handling."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from math import isfinite
from typing import cast

from unio_collector.privacy.recommendation.fields import VOCABULARIES
from unio_collector.privacy.recommendation.sdk.vocabulary import VOCABULARIES as SDK_VOCABULARIES


def valid_value(value: object, kind: str, *, nullable: bool) -> bool | None:
    """Validate specialized kinds; ordinary kinds use the canonical base policy."""
    if value is None:
        return nullable
    choices = VOCABULARIES.get(kind) or SDK_VOCABULARIES.get(kind)
    if choices is not None:
        return isinstance(value, str) and value in choices
    if kind == "version":
        return type(value) is int and value == 1
    if kind == "timestamp":
        return _aware_timestamp(value)
    if kind in {"finite_number", "financial_scalar", "financial_string", "financial_union"}:
        return _finite_value(value, kind)
    return None


def _aware_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _finite_value(value: object, kind: str) -> bool:
    if kind == "financial_union" and isinstance(value, dict):
        return True
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return False
    if kind == "financial_string" and not isinstance(value, str):
        return False
    if kind == "finite_number" and not isinstance(value, int | float):
        return False
    try:
        return Decimal(str(value)).is_finite()
    except InvalidOperation:
        return False


def public_number(value: object, spec: tuple[str, str, bool] | None) -> bool:
    """Recognize only declared operational numbers, never strings or financial data."""
    if spec is None or spec[1] != "safe_metadata":
        return False
    if spec[0] == "count":
        return type(value) is int and value >= 0
    return spec[0] == "finite_number" and type(value) in {int, float} and isfinite(cast("int|float", value))
