from __future__ import annotations  # noqa: D100

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any, cast

from unio_collector.scanners.network.cloudfront_alb_protection.coverage_record import (
    OriginProtectionCoverageRecord,
)

if TYPE_CHECKING:
    from unio_collector.scanners.network.cloudfront_alb_protection.load_balancer_record import (
        AlbOriginLoadBalancerRecord,
    )
    from unio_collector.scanners.network.cloudfront_alb_protection.origin_record import (
        CloudFrontAlbOriginRecord,
    )
    from unio_collector.scanners.network.cloudfront_alb_protection.vpc_origin_record import (
        CloudFrontVpcOriginRecord,
    )
    from unio_collector.scanners.scanner.context import ScannerContext


def origin_source_restriction(origin: dict[str, Any]) -> str:
    """Classify an explicit CloudFront origin source restriction."""
    if origin.get("OriginAccessControlId"):
        return "origin_access_control"
    if origin.get("VpcOriginConfig"):
        return "cloudfront_vpc_origin"
    return ""


def collect_items(
    client: Any,  # noqa: ANN401
    operation: str,
    *,
    list_key: str,
    item_key: str,
    **operation_kwargs: object,
) -> list[dict[str, Any]]:
    """Collect a paginated or single-response list deterministically."""
    paginator_getter = getattr(client, "get_paginator", None)
    if callable(paginator_getter):
        try:
            paginator = paginator_getter(operation)
            pages = cast("Any", paginator).paginate(**operation_kwargs)
            return [item for page in pages for item in page_items(page, list_key, item_key)]
        except Exception:  # noqa: BLE001
            response = getattr(client, operation)(**operation_kwargs)
            return page_items(response, list_key, item_key)
    response = getattr(client, operation)(**operation_kwargs)
    return page_items(response, list_key, item_key)


def host_forwarding_states(
    client: Any,  # noqa: ANN401
    distribution: dict[str, Any],
    limitations: list[str],
    coverage: list[OriginProtectionCoverageRecord],
) -> dict[str, str]:
    """Collect origin request-policy host forwarding states."""
    behaviors: list[dict[str, Any]] = []
    default_behavior = distribution.get("DefaultCacheBehavior")
    if isinstance(default_behavior, dict):
        behaviors.append(default_behavior)
    cache_behaviors = distribution.get("CacheBehaviors")
    if isinstance(cache_behaviors, dict) and isinstance(cache_behaviors.get("Items"), list):
        behaviors.extend(item for item in cache_behaviors["Items"] if isinstance(item, dict))
    states: dict[str, list[str]] = {}
    for behavior in behaviors:
        origin_id = str(behavior.get("TargetOriginId") or "")
        if not origin_id:
            continue
        policy_id = str(behavior.get("OriginRequestPolicyId") or "")
        if not policy_id:
            forwarded = behavior.get("ForwardedValues")
            headers = forwarded.get("Headers") if isinstance(forwarded, dict) else None
            values = headers.get("Items", []) if isinstance(headers, dict) else []
            state = "viewer_host_possible" if any(str(item).casefold() == "host" for item in values) else "origin_domain"
            states.setdefault(origin_id, []).append(state)
            continue
        try:
            response = client.get_origin_request_policy(Id=policy_id)
            policy = response.get("OriginRequestPolicy")
            config = policy.get("OriginRequestPolicyConfig") if isinstance(policy, dict) else None
            headers = config.get("HeadersConfig") if isinstance(config, dict) else None
            behavior_name = str(headers.get("HeaderBehavior") or "") if isinstance(headers, dict) else ""
            header_items = headers.get("Headers", {}).get("Items", []) if isinstance(headers, dict) and isinstance(headers.get("Headers"), dict) else []
            forwards_host = behavior_name in {"allViewer", "allViewerAndWhitelistCloudFront"} or any(str(item).casefold() == "host" for item in header_items)
            states.setdefault(origin_id, []).append("viewer_host_possible" if forwards_host else "origin_domain")
            coverage.append(
                OriginProtectionCoverageRecord(
                    policy_id,
                    "origin_request_policy",
                    "collected",
                    evidence_ref=f"cloudfront-origin-request-policy:{policy_id}",
                ),
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"CloudFront origin request policy evidence unavailable for {policy_id}: {exc}"
            limitations.append(msg)
            states.setdefault(origin_id, []).append("unknown")
            coverage.append(OriginProtectionCoverageRecord(policy_id, "origin_request_policy", "unavailable", limitation=msg))
    return {
        origin_id: ("unknown" if "unknown" in values else "viewer_host_possible" if "viewer_host_possible" in values else "origin_domain")
        for origin_id, values in states.items()
    }


def action_types(value: object) -> tuple[str, ...]:
    """Return sanitized action types."""
    if not isinstance(value, list):
        return ()
    return tuple(sorted({str(item.get("Type") or "") for item in value if isinstance(item, dict) and item.get("Type")}))


def fixed_response_status(value: object) -> str:
    """Return only a fixed-response status code."""
    if not isinstance(value, list):
        return ""
    for action in value:
        if not isinstance(action, dict) or action.get("Type") != "fixed-response":
            continue
        config = action.get("FixedResponseConfig")
        if isinstance(config, dict):
            return str(config.get("StatusCode") or "")
    return ""


def is_default_deny(value: object) -> bool:
    """Return whether an action is a 4xx fixed response."""
    status = fixed_response_status(value)
    return len(status) == 3 and status.startswith("4")  # noqa: PLR2004


def condition_values(conditions: list[object], field: str) -> tuple[str, ...]:
    """Extract non-secret condition values for the requested field."""
    values: list[str] = []
    for condition in conditions:
        if not isinstance(condition, dict) or str(condition.get("Field") or "") != field:
            continue
        raw = condition.get("Values")
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
        config = condition.get("HostHeaderConfig") if field == "host-header" else None
        if isinstance(config, dict) and isinstance(config.get("Values"), list):
            values.extend(str(item) for item in config["Values"])
    return tuple(sorted(set(values)))


def http_header_conditions(conditions: list[object]) -> dict[str, tuple[str, ...]]:
    """Extract transient HTTP-header conditions for in-memory comparison."""
    result: dict[str, tuple[str, ...]] = {}
    for condition in conditions:
        if not isinstance(condition, dict) or str(condition.get("Field") or "") != "http-header":
            continue
        config = condition.get("HttpHeaderConfig")
        if not isinstance(config, dict) or not config.get("HttpHeaderName"):
            continue
        values = config.get("Values")
        result[str(config["HttpHeaderName"])] = tuple(str(item) for item in values) if isinstance(values, list) else ()
    return result


def host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    """Match a host against explicit listener-rule host patterns."""
    return any(fnmatchcase(host.casefold(), pattern.casefold()) for pattern in patterns)


def origins_by_load_balancer(
    origins: list[CloudFrontAlbOriginRecord],
    vpc_origins: list[CloudFrontVpcOriginRecord],
    load_balancers: list[AlbOriginLoadBalancerRecord],
) -> dict[str, list[CloudFrontAlbOriginRecord]]:
    """Correlate origins only through explicit collected identifiers."""
    vpc_by_id = {item.vpc_origin_id: item for item in vpc_origins}
    result: dict[str, list[CloudFrontAlbOriginRecord]] = {}
    for origin in origins:
        vpc = vpc_by_id.get(origin.vpc_origin_id)
        for load_balancer in load_balancers:
            matched = (
                vpc is not None and vpc.endpoint_arn == load_balancer.arn
                if origin.vpc_origin_id
                else origin.origin_domain_name.casefold()
                in {
                    load_balancer.dns_name.casefold(),
                    load_balancer.name.casefold(),
                    load_balancer.arn.casefold(),
                }
            )
            if matched:
                result.setdefault(load_balancer.arn, []).append(origin)
    return result


def page_items(page: dict[str, Any], list_key: str, item_key: str) -> list[dict[str, Any]]:
    """Read typed items from either nested or direct AWS response lists."""
    container = page.get(list_key)
    items = container.get(item_key, []) if isinstance(container, dict) else page.get(item_key, [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def chunks(values: list[str], *, size: int) -> list[list[str]]:
    """Split values into deterministic API request chunks."""
    return [values[index : index + size] for index in range(0, len(values), size)]


def to_int(value: object) -> int | None:
    """Coerce an AWS scalar to an integer when possible."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def selected_or_available_regions(context: ScannerContext, service_name: str) -> list[str]:
    """Return selected non-global regions or service availability."""
    selected = context.options.get_selected_regions()
    regions = [region for region in selected if region != "global"] if selected else context.security.session.get_available_regions(service_name)
    return regions or ["us-east-1"]
