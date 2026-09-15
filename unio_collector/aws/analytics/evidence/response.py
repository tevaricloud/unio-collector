"""Validate analytics metadata pages without treating missing lists as absence."""

from __future__ import annotations

from typing import Any


def collect_analytics_page_rows(pages: list[dict[str, Any]], key: str, errors: list[str], operation: str) -> list[dict[str, Any]]:
    """Retain provider objects while recording malformed or missing list evidence."""
    rows: list[dict[str, Any]] = []
    if not pages:
        errors.append(f"{operation}:UnavailableEvidence")
    for page in pages:
        values = page.get(key)
        if not isinstance(values, list):
            errors.append(f"{operation}:UnavailableEvidence")
            continue
        if any(not isinstance(value, dict) for value in values):
            errors.append(f"{operation}:MalformedEvidence")
        rows.extend(value for value in values if isinstance(value, dict))
    return rows
