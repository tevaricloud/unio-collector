from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.pricing.unit_rate import UnitRate

if TYPE_CHECKING:
    from unio_collector.core.scan.period import ScanPeriod


def extract_on_demand_rate(product: dict[str, Any]) -> UnitRate | None:  # noqa: D103
    terms = product.get("terms", {}).get("OnDemand", {})
    for term in terms.values():
        for dimension in term.get("priceDimensions", {}).values():
            unit = str(dimension.get("unit") or "")
            prices = dimension.get("pricePerUnit", {})
            if not isinstance(prices, dict) or "USD" not in prices:
                continue
            amount = Decimal(str(prices["USD"]))
            if amount < 0:
                continue
            return UnitRate(
                amount=amount,
                currency="USD",
                unit=unit,
                source="AWS Price List Query API",
            )
    return None


def normalize_to_monthly(amount: Decimal, scan_period: ScanPeriod) -> Decimal:  # noqa: D103
    if amount <= 0:
        return Decimal(0)
    return (amount * Decimal(30) / Decimal(scan_period.duration_days)).quantize(
        Decimal("0.01"),
    )


def term_match_filter(field: str, value: str) -> dict[str, str]:  # noqa: D103
    return {"Type": "TERM_MATCH", "Field": field, "Value": value}


def decimal_or_none(value: Any) -> Decimal | None:  # noqa: ANN401, D103
    if value in (None, ""):
        return None
    try:
        return Decimal(str(value))
    except Exception:  # noqa: BLE001
        return None


def int_or_zero(value: Any) -> int:  # noqa: ANN401, D103
    try:
        return int(str(value or "0"))
    except Exception:  # noqa: BLE001
        return 0


def first_signal(finding: Any) -> dict[str, Any]:  # noqa: ANN401, D103
    if not finding.source_signals:
        return {}
    first = finding.source_signals[0]
    return first if isinstance(first, dict) else {}


def format_status_label(value: str) -> str:  # noqa: D103
    cleaned = value.replace("_", " ").strip()
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Unknown"
