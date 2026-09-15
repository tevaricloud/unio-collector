"""Admit the fixed offline service-cost fixture without private interpretation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.core.cost_period import CostPeriod

if TYPE_CHECKING:
    from pathlib import Path

INVALID_FIXTURE = "Fixture collection requires complete finite service-cost evidence."


@dataclass(frozen=True)
class AwsCollectionFixture:
    """Validated factual inputs for the existing service-cost fixture workflow."""

    costs: CostExplorerResult
    currency: str
    account_context: dict[str, Any]

    @classmethod
    def read(cls, path: Path, *, default_currency: str) -> AwsCollectionFixture:
        """Reject missing or malformed evidence before a successful result exists."""
        try:
            raw = load_json_object(path.read_text(encoding="utf-8"))
            return cls._from_payload(raw, default_currency)
        except (KeyError, TypeError, ValueError, ArithmeticError):
            raise ValueError(INVALID_FIXTURE) from None

    @classmethod
    def _from_payload(cls, raw: dict[str, Any], default_currency: str) -> AwsCollectionFixture:
        rows = raw.get("service_costs")
        if not isinstance(rows, list):
            raise ValueError(INVALID_FIXTURE)
        for row in rows:
            _validate_cost_row(row)
        account_context = raw.get("account_context", {})
        if not isinstance(account_context, dict):
            raise ValueError(INVALID_FIXTURE)
        currency = raw.get("currency") or default_currency
        if not isinstance(currency, str) or not currency.strip():
            raise ValueError(INVALID_FIXTURE)
        costs = CostExplorerResult(
            previous_period=CostPeriod.model_validate(raw["previous_period"]),
            current_period=CostPeriod.model_validate(raw["current_period"]),
            service_costs=rows,
        )
        return cls(costs=costs, currency=currency, account_context=dict(account_context))


def _validate_cost_row(row: object) -> None:
    if not isinstance(row, dict):
        raise ValueError(INVALID_FIXTURE)
    service = row.get("service_name")
    if not isinstance(service, str) or not service.strip():
        raise ValueError(INVALID_FIXTURE)
    region = row.get("region", "global")
    if not isinstance(region, str) or not region.strip():
        raise ValueError(INVALID_FIXTURE)
    for key in ("previous_cost", "current_cost"):
        value = row.get(key)
        if isinstance(value, bool) or not isinstance(value, str | int | float | Decimal) or not Decimal(str(value)).is_finite():
            raise ValueError(INVALID_FIXTURE)
