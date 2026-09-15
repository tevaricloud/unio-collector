from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.load_balancer.constants import (
    LOAD_BALANCER_TARGET_HEALTH_DETAIL_MODES,
)


def normalize_load_balancer_target_health_detail_mode(value: object) -> str:  # noqa: D103
    if value is None:
        return "full"
    normalized = str(value).strip().lower()
    if normalized in LOAD_BALANCER_TARGET_HEALTH_DETAIL_MODES:
        return normalized
    msg = "Load balancer target_health_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(
        msg,
    )


def load_balancer_dimension(load_balancer: dict[str, Any]) -> str | None:  # noqa: D103
    arn = load_balancer.get("LoadBalancerArn")
    if not isinstance(arn, str) or ":loadbalancer/" not in arn:
        return None
    return arn.split(":loadbalancer/", 1)[1]


def tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if tag.get("Key")}


def parse_bool_option(value: object, *, default: bool) -> bool:  # noqa: D103
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}
