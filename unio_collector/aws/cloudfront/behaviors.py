# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudfront.facts import CloudFrontBehaviorHistogram
from unio_collector.aws.cloudfront.paginator import CloudFrontMarkerPaginator

if TYPE_CHECKING:
    from collections.abc import Callable

CLOUDFRONT_CONTROL_PLANE_REGION = "us-east-1"
CLOUDFRONT_METRIC_REGION_DIMENSION = "Global"
CLOUDFRONT_METRIC_PERIOD_SECONDS = 86400
MAX_CLOUDWATCH_METRIC_QUERIES = 500
MAX_INVALIDATION_DISTRIBUTIONS = 50


class CloudFrontBehaviorMixin:  # noqa: D101
    def _collect_behavior_histogram(
        self,
        distributions: list[dict[str, Any]],
    ) -> CloudFrontBehaviorHistogram:
        return CloudFrontBehaviorHistogram.from_flags(
            (
                self._forwards_query_strings(behavior),
                self._forwards_all_cookies(behavior),
                self._forwards_headers(behavior),
                self._is_zero_ttl_behavior(behavior),
                bool(behavior.get("OriginRequestPolicyId")),
                isinstance(behavior.get("ForwardedValues"), dict),
            )
            for distribution in distributions
            for behavior in self._get_cache_behavior_items(distribution)
        )

    def _count_cache_behaviors_matching(
        self,
        distribution: dict[str, Any],
        predicate: Callable[[dict[str, Any]], bool],
    ) -> int:
        return sum(1 for behavior in self._get_cache_behavior_items(distribution) if predicate(behavior))

    def _is_compression_disabled(self, behavior: dict[str, Any]) -> bool:
        return behavior.get("Compress") is False

    def _forwards_query_strings(self, behavior: dict[str, Any]) -> bool:
        forwarded_values = behavior.get("ForwardedValues", {})
        if not isinstance(forwarded_values, dict):
            return False
        return bool(forwarded_values.get("QueryString"))

    def _forwards_all_cookies(self, behavior: dict[str, Any]) -> bool:
        forwarded_values = behavior.get("ForwardedValues", {})
        if not isinstance(forwarded_values, dict):
            return False
        cookies = forwarded_values.get("Cookies", {})
        if not isinstance(cookies, dict):
            return False
        return str(cookies.get("Forward") or "").lower() == "all"

    def _forwards_headers(self, behavior: dict[str, Any]) -> bool:
        forwarded_values = behavior.get("ForwardedValues", {})
        if not isinstance(forwarded_values, dict):
            return False
        headers = forwarded_values.get("Headers", {})
        if not isinstance(headers, dict):
            return False
        quantity = headers.get("Quantity", 0)
        return isinstance(quantity, int) and quantity > 0

    def _is_zero_ttl_behavior(self, behavior: dict[str, Any]) -> bool:
        ttl_values = [
            behavior.get("MinTTL"),
            behavior.get("DefaultTTL"),
            behavior.get("MaxTTL"),
        ]
        numeric_ttls = [value for value in ttl_values if isinstance(value, int)]
        return bool(numeric_ttls) and all(value == 0 for value in numeric_ttls)

    def _count_viewer_protocol_policies(
        self,
        distribution: dict[str, Any],
        policy: str,
    ) -> int:
        return self._count_cache_behaviors_matching(
            distribution,
            lambda behavior: str(behavior.get("ViewerProtocolPolicy") or "").lower() == policy,
        )

    def _allows_all_methods(self, behavior: dict[str, Any]) -> bool:
        allowed_methods = behavior.get("AllowedMethods", {})
        if not isinstance(allowed_methods, dict):
            return False
        items = allowed_methods.get("Items", [])
        if not isinstance(items, list):
            return False
        methods = {str(item).upper() for item in items}
        return {"DELETE", "PATCH", "POST", "PUT"}.issubset(methods)

    def _count_origin_protocol_policies(
        self,
        distribution: dict[str, Any],
        policy: str,
    ) -> int:
        return sum(
            1
            for origin in self._get_origin_items(distribution)
            if str(
                origin.get("CustomOriginConfig", {}).get("OriginProtocolPolicy") if isinstance(origin.get("CustomOriginConfig"), dict) else "",
            ).lower()
            == policy
        )

    def _collect_sample_origin_domains(
        self,
        distributions: list[dict[str, Any]],
    ) -> list[str]:
        return self._values.limit_samples(
            (str(origin.get("DomainName") or "").strip() for distribution in distributions for origin in self._get_origin_items(distribution)),
            limit=25,
        )

    def _collect_sample_price_classes(
        self,
        distributions: list[dict[str, Any]],
    ) -> list[str]:
        return self._values.limit_samples(str(distribution.get("PriceClass") or "").strip() for distribution in distributions)

    def _collect_sample_logging_buckets(
        self,
        distributions: list[dict[str, Any]],
        *,
        limit: int = 10,
    ) -> list[str]:
        return self._values.limit_samples(
            (
                str(distribution.get("Logging", {}).get("Bucket") or "").strip()
                for distribution in distributions
                if isinstance(distribution.get("Logging"), dict) and distribution.get("Logging", {}).get("Enabled")
            ),
            limit=limit,
        )

    def _collect_sample_behavior_values(
        self,
        distributions: list[dict[str, Any]],
        key: str,
        *,
        limit: int = 10,
    ) -> list[str]:
        return self._values.limit_samples(
            (str(behavior.get(key) or "").strip() for distribution in distributions for behavior in self._get_cache_behavior_items(distribution)),
            limit=limit,
        )

    def _collect_sample_viewer_protocol_policies(
        self,
        distributions: list[dict[str, Any]],
    ) -> list[str]:
        return self._collect_sample_behavior_values(
            distributions,
            "ViewerProtocolPolicy",
        )

    def _collect_sample_origin_protocol_policies(
        self,
        distributions: list[dict[str, Any]],
    ) -> list[str]:
        return self._values.limit_samples(
            str(
                origin.get("CustomOriginConfig", {}).get("OriginProtocolPolicy") or "",
            ).strip()
            for distribution in distributions
            for origin in self._get_origin_items(distribution)
            if isinstance(origin.get("CustomOriginConfig"), dict)
        )

    def _get_origin_items(
        self,
        distribution: dict[str, Any],
    ) -> list[dict[str, Any]]:
        origins = distribution.get("Origins", {})
        if not isinstance(origins, dict):
            return []
        items = origins.get("Items", [])
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    def _get_cache_behavior_items(
        self,
        distribution: dict[str, Any],
    ) -> list[dict[str, Any]]:
        default_behavior = distribution.get("DefaultCacheBehavior")
        if not isinstance(default_behavior, dict):
            msg = "CloudFront default cache behavior is unavailable."
            raise ValueError(msg)
        return [default_behavior, *self._get_ordered_cache_behavior_items(distribution)]

    def _get_ordered_cache_behavior_items(
        self,
        distribution: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return CloudFrontMarkerPaginator.validate_items(distribution.get("CacheBehaviors"))
