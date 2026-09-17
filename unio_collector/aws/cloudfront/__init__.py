from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws.cloudfront.behaviors import CloudFrontBehaviorMixin
from unio_collector.aws.cloudfront.distribution import CloudFrontDistributionRecord
from unio_collector.aws.cloudfront.helpers import (
    build_metric_collection_reason,
    calculate_average,
    normalize_cloudfront_invalidation_detail_mode,
    resolve_metric_collection_status,
)
from unio_collector.aws.cloudfront.metric_summary import CloudFrontMetricSummary
from unio_collector.aws.cloudfront.metrics import CloudFrontMetricMixin
from unio_collector.aws.cloudfront.paginator import CloudFrontMarkerPaginator
from unio_collector.aws.errors import get_aws_error_code
from unio_collector.aws.inventory_helpers import AwsInventoryValueHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.core.scan.period import ScanPeriod

CLOUDFRONT_CONTROL_PLANE_REGION = "us-east-1"
CLOUDFRONT_METRIC_REGION_DIMENSION = "Global"
CLOUDFRONT_METRIC_PERIOD_SECONDS = 86400
MAX_CLOUDWATCH_METRIC_QUERIES = 500
MAX_INVALIDATION_DISTRIBUTIONS = 50


class CloudFrontInventoryCollector(CloudFrontMetricMixin, CloudFrontBehaviorMixin):
    """Collect read-only CloudFront inventory for cost governance review."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        scan_period: ScanPeriod | None = None,
        collect_metrics: bool = False,
        invalidation_detail_mode: object = "full",
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.scan_period = scan_period
        self.collect_metrics = collect_metrics
        self.invalidation_detail_mode = normalize_cloudfront_invalidation_detail_mode(
            invalidation_detail_mode,
        )
        self._values = AwsInventoryValueHelper()
        self._marker_paginator = CloudFrontMarkerPaginator(self._values)

    def collect_distribution_record(self) -> CloudFrontDistributionRecord:  # noqa: D102
        client = self.session.create_client(
            "cloudfront",
            region_name=CLOUDFRONT_CONTROL_PLANE_REGION,
            audit_context=self.audit_context,
        )
        distributions = self._collect_distributions(client)
        behavior_histogram = self._collect_behavior_histogram(distributions)
        tag_summary = self._collect_distribution_tag_summary(
            client,
            distributions,
        )
        invalidation_summary = self._collect_invalidation_summary_if_enabled(
            client,
            distributions,
        )
        metric_summary = self._collect_distribution_metric_summary(distributions)
        return CloudFrontDistributionRecord(
            account_id=self.account_id,
            collection_evidence_version=1,
            behavior_histogram=behavior_histogram,
            distribution_count=len(distributions),
            enabled_distribution_count=sum(1 for item in distributions if bool(item.get("Enabled"))),
            disabled_distribution_count=sum(1 for item in distributions if not bool(item.get("Enabled"))),
            origin_count=sum(self._get_nested_quantity(item, "Origins") for item in distributions),
            custom_origin_count=sum(self._count_origins(item, origin_type="custom") for item in distributions),
            s3_origin_count=sum(self._count_origins(item, origin_type="s3") for item in distributions),
            s3_rest_origin_count=sum(self._count_origin_domains(item, "s3_rest") for item in distributions),
            s3_website_origin_count=sum(self._count_origin_domains(item, "s3_website") for item in distributions),
            aws_service_origin_count=sum(self._count_origin_domains(item, "aws_service") for item in distributions),
            unknown_origin_count=sum(self._count_origin_domains(item, "unknown") for item in distributions),
            load_balancer_origin_count=sum(self._count_origin_domains(item, "load_balancer") for item in distributions),
            api_gateway_origin_count=sum(self._count_origin_domains(item, "api_gateway") for item in distributions),
            custom_domain_origin_count=sum(self._count_origin_domains(item, "custom_domain") for item in distributions),
            origin_shield_enabled_count=sum(self._count_origin_shield_enabled(item) for item in distributions),
            cache_behavior_count=sum(len(self._get_cache_behavior_items(item)) for item in distributions),
            ordered_cache_behavior_count=sum(len(self._get_ordered_cache_behavior_items(item)) for item in distributions),
            price_class_all_count=sum(1 for item in distributions if str(item.get("PriceClass") or "") == "PriceClass_All"),
            cache_policy_behavior_count=sum(self._count_cache_behaviors_with_key(item, "CachePolicyId") for item in distributions),
            origin_request_policy_behavior_count=sum(self._count_cache_behaviors_with_key(item, "OriginRequestPolicyId") for item in distributions),
            legacy_forwarded_values_behavior_count=sum(self._count_legacy_forwarded_values_behaviors(item) for item in distributions),
            compression_disabled_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._is_compression_disabled,
                )
                for item in distributions
            ),
            query_string_forwarding_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._forwards_query_strings,
                )
                for item in distributions
            ),
            all_cookie_forwarding_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._forwards_all_cookies,
                )
                for item in distributions
            ),
            header_forwarding_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._forwards_headers,
                )
                for item in distributions
            ),
            zero_ttl_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._is_zero_ttl_behavior,
                )
                for item in distributions
            ),
            allow_all_viewer_protocol_policy_count=sum(self._count_viewer_protocol_policies(item, "allow-all") for item in distributions),
            redirect_to_https_viewer_protocol_policy_count=sum(self._count_viewer_protocol_policies(item, "redirect-to-https") for item in distributions),
            https_only_viewer_protocol_policy_count=sum(self._count_viewer_protocol_policies(item, "https-only") for item in distributions),
            all_methods_allowed_behavior_count=sum(
                self._count_cache_behaviors_matching(
                    item,
                    self._allows_all_methods,
                )
                for item in distributions
            ),
            http_only_origin_policy_count=sum(self._count_origin_protocol_policies(item, "http-only") for item in distributions),
            https_only_origin_policy_count=sum(self._count_origin_protocol_policies(item, "https-only") for item in distributions),
            match_viewer_origin_policy_count=sum(self._count_origin_protocol_policies(item, "match-viewer") for item in distributions),
            logging_enabled_count=sum(1 for item in distributions if bool(item.get("Logging", {}).get("Enabled"))),
            logging_bucket_count=len(
                self._collect_sample_logging_buckets(distributions, limit=10000),
            ),
            web_acl_associated_count=sum(1 for item in distributions if bool(item.get("WebACLId"))),
            tagged_distribution_count=tag_summary["tagged_distribution_count"],
            tag_evidence_complete=not tag_summary["tag_collection_errors"],
            invalidation_distribution_count=(invalidation_summary["invalidation_distribution_count"]),
            invalidation_batch_count=invalidation_summary["invalidation_batch_count"],
            invalidation_path_count=invalidation_summary["invalidation_path_count"],
            invalidation_detail_collected=(self.invalidation_detail_mode == "full"),
            invalidation_path_evidence_complete=invalidation_summary["invalidation_path_evidence_complete"],
            invalidation_collection_limited=invalidation_summary["invalidation_collection_limited"],
            wildcard_invalidation_path_count=invalidation_summary["wildcard_invalidation_path_count"],
            recent_invalidation_batch_count=invalidation_summary["recent_invalidation_batch_count"],
            recent_invalidation_path_count=invalidation_summary["recent_invalidation_path_count"],
            recent_wildcard_invalidation_path_count=invalidation_summary["recent_wildcard_invalidation_path_count"],
            sample_distribution_ids=[str(item.get("Id")) for item in distributions[:25] if item.get("Id")],
            sample_distribution_domains=[str(item.get("DomainName")) for item in distributions[:25] if item.get("DomainName")],
            sample_origin_domains=self._collect_sample_origin_domains(
                distributions,
            ),
            sample_invalidation_distribution_ids=invalidation_summary["sample_invalidation_distribution_ids"],
            sample_price_classes=self._collect_sample_price_classes(distributions),
            sample_logging_buckets=self._collect_sample_logging_buckets(
                distributions,
            ),
            sample_cache_policy_ids=self._collect_sample_behavior_values(
                distributions,
                "CachePolicyId",
            ),
            sample_origin_request_policy_ids=(
                self._collect_sample_behavior_values(
                    distributions,
                    "OriginRequestPolicyId",
                )
            ),
            sample_viewer_protocol_policies=(self._collect_sample_viewer_protocol_policies(distributions)),
            sample_origin_protocol_policies=(self._collect_sample_origin_protocol_policies(distributions)),
            invalidation_collection_errors=invalidation_summary["invalidation_collection_errors"],
            tag_collection_errors=tag_summary["tag_collection_errors"],
            metric_collection_status=metric_summary.metric_collection_status,
            metric_collection_reason=metric_summary.metric_collection_reason,
            metric_distribution_count=metric_summary.metric_distribution_count,
            metric_datapoint_count=metric_summary.metric_datapoint_count,
            request_sum=metric_summary.request_sum,
            bytes_downloaded_sum=metric_summary.bytes_downloaded_sum,
            bytes_uploaded_sum=metric_summary.bytes_uploaded_sum,
            four_xx_error_rate_average=(metric_summary.four_xx_error_rate_average),
            five_xx_error_rate_average=(metric_summary.five_xx_error_rate_average),
            metric_collection_errors=metric_summary.metric_collection_errors,
        )

    def _collect_distributions(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        return self._marker_paginator.collect_items(
            client,
            "list_distributions",
            list_key="DistributionList",
        )

    def _collect_distribution_tag_summary(
        self,
        client: Any,  # noqa: ANN401
        distributions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tagged_distribution_count = 0
        tag_collection_errors: list[str] = []
        for distribution in distributions:
            arn = distribution.get("ARN")
            if not arn:
                tag_collection_errors.append("MissingDistributionArn")
                continue
            try:
                response = client.list_tags_for_resource(Resource=str(arn))
            except ClientError as exc:
                code = get_aws_error_code(exc) or exc.__class__.__name__
                tag_collection_errors.append(str(code))
                continue
            container = response.get("Tags") if isinstance(response, dict) else None
            tags = container.get("Items") if isinstance(container, dict) else None
            if not isinstance(tags, list) or any(not isinstance(tag, dict) or "Key" not in tag or "Value" not in tag for tag in tags):
                tag_collection_errors.append("IncompleteTagEvidence")
                continue
            if tags:
                tagged_distribution_count += 1
        return {
            "tagged_distribution_count": tagged_distribution_count,
            "tag_collection_errors": sorted(set(tag_collection_errors)),
        }

    def _collect_invalidation_summary_if_enabled(
        self,
        client: Any,  # noqa: ANN401
        distributions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if self.invalidation_detail_mode == "summary":
            return self._build_empty_invalidation_summary()
        return self._collect_invalidation_summary(client, distributions)


__all__ = [
    "CLOUDFRONT_CONTROL_PLANE_REGION",
    "CLOUDFRONT_METRIC_PERIOD_SECONDS",
    "CLOUDFRONT_METRIC_REGION_DIMENSION",
    "MAX_CLOUDWATCH_METRIC_QUERIES",
    "MAX_INVALIDATION_DISTRIBUTIONS",
    "CloudFrontDistributionRecord",
    "CloudFrontInventoryCollector",
    "CloudFrontMarkerPaginator",
    "CloudFrontMetricSummary",
    "build_metric_collection_reason",
    "calculate_average",
    "normalize_cloudfront_invalidation_detail_mode",
    "resolve_metric_collection_status",
]
