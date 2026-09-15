"""Lazy compatibility exports for core application helpers."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "BackgroundJobResult": (
        "unio_collector.core.background.job.result",
        "BackgroundJobResult",
    ),
    "BackgroundJobRunner": (
        "unio_collector.core.background.job.runner",
        "BackgroundJobRunner",
    ),
    "UnioBaseModel": ("unio_collector.core.base_model", "UnioBaseModel"),
    "CostPeriod": ("unio_collector.core.cost_period", "CostPeriod"),
    "JobStatus": ("unio_collector.core.background.job.result", "JobStatus"),
    "PeriodKind": ("unio_collector.core.scan.period", "PeriodKind"),
    "ScanPeriod": ("unio_collector.core.scan.period", "ScanPeriod"),
    "ScanPeriodResolver": (
        "unio_collector.core.scan.period_resolver",
        "ScanPeriodResolver",
    ),
    "days_in_month": ("unio_collector.core.period_helpers", "days_in_month"),
    "parse_iso_date": ("unio_collector.core.period_helpers", "parse_iso_date"),
    "subtract_months": ("unio_collector.core.period_helpers", "subtract_months"),
}

__all__ = [
    "BackgroundJobResult",
    "BackgroundJobRunner",
    "CostPeriod",
    "JobStatus",
    "PeriodKind",
    "ScanPeriod",
    "ScanPeriodResolver",
    "UnioBaseModel",
    "days_in_month",
    "parse_iso_date",
    "subtract_months",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical core export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
