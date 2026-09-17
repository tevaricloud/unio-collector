from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CostExplorerEvidenceLabelBuilder:
    """Builds scanner-facing evidence labels for Cost Explorer cache notes."""

    def build_service_costs_label(self) -> str:  # noqa: D102
        return "Cost Explorer service-cost baseline"

    def build_daily_costs_label(self, *, group_keys: tuple[str, ...]) -> str:  # noqa: D102
        return f"Cost Explorer daily costs grouped by {', '.join(group_keys)}"
