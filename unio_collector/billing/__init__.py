"""Typed AWS billing baseline and savings-percentage services."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.billing.baseline import LastCompletedMonthBillingBaseline
from unio_collector.billing.period import CompletedMonthPeriod
from unio_collector.billing.period_resolver import CompletedMonthPeriodResolver

if TYPE_CHECKING:
    from unio_collector.billing.calculator import KnownSavingsSpendPercentageCalculator
    from unio_collector.billing.percentage.result import KnownSavingsSpendPercentage
    from unio_collector.billing.percentage.status import SavingsPercentageStatus

__all__ = [
    "CompletedMonthPeriod",
    "CompletedMonthPeriodResolver",
    "KnownSavingsSpendPercentage",
    "KnownSavingsSpendPercentageCalculator",
    "LastCompletedMonthBillingBaseline",
    "SavingsPercentageStatus",
]


_EXPORTS: dict[str, tuple[str, str]] = {
    "KnownSavingsSpendPercentageCalculator": ("unio_collector.billing.calculator", "KnownSavingsSpendPercentageCalculator"),
    "KnownSavingsSpendPercentage": ("unio_collector.billing.percentage.result", "KnownSavingsSpendPercentage"),
    "SavingsPercentageStatus": ("unio_collector.billing.percentage.status", "SavingsPercentageStatus"),
}


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical application export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
