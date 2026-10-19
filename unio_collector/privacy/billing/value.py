"""Finite typed billing SDK value admission; no provider imports or exemptions."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any


def _within(value: float, node: dict[str, Any]) -> bool:
    """Respect the pinned SDK numeric or string-length bounds."""
    return (node.get("minimum") is None or value >= node["minimum"]) and (node.get("maximum") is None or value <= node["maximum"])


def _date(value: object) -> bool:
    """Admit only actual serialized ISO provider timestamps."""
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _string(value: object, node: dict[str, Any]) -> bool:
    """Validate enums, dates and finite financial strings before treatment."""
    if not isinstance(value, str) or (node.get("enum") and value not in node["enum"]):
        return False
    if not _within(len(value), node):
        return False
    if node.get("iso_date") and not _date(value):
        return False
    if node.get("numeric"):
        try:
            return Decimal(value).is_finite()
        except InvalidOperation:
            return False
    return True


def valid_shape(value: object, node: dict[str, Any]) -> bool:
    """Reject JSON null even for SDK types historically named Nullable."""
    kind = node["kind"]
    if kind == "structure":
        return isinstance(value, dict) and set(node.get("required", [])) <= set(value) and (not node.get("union") or len(value) == 1)
    if kind in {"map", "list", "boolean"}:
        return isinstance(value, {"map": dict, "list": list, "boolean": bool}[kind])
    if kind in {"integer", "long"}:
        return type(value) is int and _within(value, node)
    if kind in {"double", "float"}:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and Decimal(str(value)).is_finite() and _within(value, node)
    if kind == "timestamp":
        return _date(value)
    return kind == "string" and _string(value, node)
