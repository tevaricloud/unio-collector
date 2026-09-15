from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING

from unio_collector.aws.xray.cost.signal import XRayCostSignal

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import CostExplorerResult


def extract_xray_cost_signal(cost_data: CostExplorerResult) -> XRayCostSignal:  # noqa: D103
    for item in cost_data.service_costs:
        service_name = str(item.get("service_name") or "")
        if not is_xray_service_name(service_name):
            continue
        previous_cost = Decimal(str(item.get("previous_cost") or "0"))
        current_cost = Decimal(str(item.get("current_cost") or "0"))
        return XRayCostSignal(
            service_name=service_name,
            previous_cost=previous_cost,
            current_cost=current_cost,
            absolute_delta=current_cost - previous_cost,
            currency=str(item.get("currency") or cost_data.current_period.currency),
        )
    return XRayCostSignal(currency=cost_data.current_period.currency)


def is_xray_service_name(service_name: str) -> bool:  # noqa: D103
    normalized = " ".join(service_name.casefold().replace("-", " ").split())
    return normalized in {
        "aws x ray",
        "aws xray",
        "amazon x ray",
        "amazon xray",
    }
