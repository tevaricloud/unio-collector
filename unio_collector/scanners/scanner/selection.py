from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.pillars import DEFAULT_SCANNER_PILLAR_POLICY

if TYPE_CHECKING:
    from unio_collector.scanners.chargeable_scanner_block import ChargeableScannerBlock


@dataclass(frozen=True)
class ScannerSelection:
    """Resolved enabled/disabled scanner set for one scan."""

    enabled_ids: tuple[str, ...]
    disabled_ids: tuple[str, ...]
    chargeable_blocks: tuple[ChargeableScannerBlock, ...] = ()
    disabled_reasons: dict[str, str] = field(default_factory=dict)
    selected_pillars: tuple[str, ...] = ()
    pillar_filter_applied: bool = False
    pillar_filter_bypass_reason: str = ""
    pillar_policy_summary: dict[str, Any] = field(default_factory=dict)
    product_id: str | None = None
    product_definition_version: str | None = None
    product_selection_source: str | None = None
    out_of_product_overrides: tuple[str, ...] = ()

    def get_disabled_reason(self, scanner_id: str) -> str | None:  # noqa: D102
        return self.disabled_reasons.get(scanner_id)

    def convert_pillar_policy_to_dict(self) -> dict[str, object]:  # noqa: D102
        if self.pillar_policy_summary:
            return dict(self.pillar_policy_summary)
        summary = DEFAULT_SCANNER_PILLAR_POLICY.build_summary(self.selected_pillars)
        summary.update(
            {
                "filter_applied": self.pillar_filter_applied,
                "bypass_reason": self.pillar_filter_bypass_reason,
            },
        )
        return summary
