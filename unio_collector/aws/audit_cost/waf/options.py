from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.audit_cost.inventory.helpers import (
    normalize_waf_association_detail_mode,
)


@dataclass(frozen=True)
class WafCostGovernanceCollectionOptions:  # noqa: D101
    association_detail_mode: str = "full"

    @classmethod
    def create(  # noqa: D102
        cls,
        *,
        association_detail_mode: object = "full",
    ) -> WafCostGovernanceCollectionOptions:
        return cls(
            association_detail_mode=normalize_waf_association_detail_mode(
                association_detail_mode,
            ),
        )

    def should_collect_association_metadata(self) -> bool:  # noqa: D102
        return self.association_detail_mode == "full"
