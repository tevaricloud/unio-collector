from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.audit_cost.inventory.helpers import (
    normalize_config_rule_detail_mode,
)


@dataclass(frozen=True)
class ConfigCostGovernanceCollectionOptions:  # noqa: D101
    rule_detail_mode: str = "full"

    @classmethod
    def create(  # noqa: D102
        cls,
        *,
        rule_detail_mode: object = "full",
    ) -> ConfigCostGovernanceCollectionOptions:
        return cls(rule_detail_mode=normalize_config_rule_detail_mode(rule_detail_mode))

    def should_collect_rule_metadata(self) -> bool:  # noqa: D102
        return self.rule_detail_mode == "full"
