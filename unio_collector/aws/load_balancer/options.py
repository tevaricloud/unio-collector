from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.load_balancer.helpers import (
    normalize_load_balancer_target_health_detail_mode,
    parse_bool_option,
)


@dataclass(frozen=True)
class LoadBalancerCollectionOptions:  # noqa: D101
    target_health_detail_mode: str = "full"
    collect_tags: bool = True

    @classmethod
    def create(  # noqa: D102
        cls,
        *,
        target_health_detail_mode: object = "full",
        collect_tags: object = True,
    ) -> LoadBalancerCollectionOptions:
        return cls(
            target_health_detail_mode=(
                normalize_load_balancer_target_health_detail_mode(
                    target_health_detail_mode,
                )
            ),
            collect_tags=parse_bool_option(collect_tags, default=True),
        )

    def should_collect_target_health(self) -> bool:  # noqa: D102
        return self.target_health_detail_mode == "full"
