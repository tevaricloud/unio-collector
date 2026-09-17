from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.aws.cloudfront.facts import CloudFrontBehaviorHistogram  # noqa: TC001


@dataclass(frozen=True)
class CloudFrontDistributionRecord:  # noqa: D101
    account_id: str
    region: str = "global"
    distribution_count: int = 0
    enabled_distribution_count: int = 0
    disabled_distribution_count: int = 0
    origin_count: int = 0
    custom_origin_count: int = 0
    s3_origin_count: int = 0
    s3_rest_origin_count: int = 0
    s3_website_origin_count: int = 0
    aws_service_origin_count: int = 0
    unknown_origin_count: int = 0
    load_balancer_origin_count: int = 0
    api_gateway_origin_count: int = 0
    custom_domain_origin_count: int = 0
    origin_shield_enabled_count: int = 0
    cache_behavior_count: int = 0
    ordered_cache_behavior_count: int = 0
    price_class_all_count: int = 0
    cache_policy_behavior_count: int = 0
    origin_request_policy_behavior_count: int = 0
    legacy_forwarded_values_behavior_count: int = 0
    cache_fragmentation_behavior_count: int = 0
    origin_request_expansion_behavior_count: int = 0
    compression_disabled_behavior_count: int = 0
    query_string_forwarding_behavior_count: int = 0
    all_cookie_forwarding_behavior_count: int = 0
    header_forwarding_behavior_count: int = 0
    zero_ttl_behavior_count: int = 0
    allow_all_viewer_protocol_policy_count: int = 0
    redirect_to_https_viewer_protocol_policy_count: int = 0
    https_only_viewer_protocol_policy_count: int = 0
    all_methods_allowed_behavior_count: int = 0
    http_only_origin_policy_count: int = 0
    https_only_origin_policy_count: int = 0
    match_viewer_origin_policy_count: int = 0
    logging_enabled_count: int = 0
    logging_bucket_count: int = 0
    web_acl_associated_count: int = 0
    tagged_distribution_count: int = 0
    invalidation_distribution_count: int = 0
    invalidation_batch_count: int = 0
    invalidation_path_count: int = 0
    invalidation_detail_collected: bool = True
    wildcard_invalidation_path_count: int = 0
    recent_invalidation_batch_count: int = 0
    recent_invalidation_path_count: int = 0
    recent_wildcard_invalidation_path_count: int = 0
    sample_distribution_ids: list[str] = field(default_factory=list)
    sample_distribution_domains: list[str] = field(default_factory=list)
    sample_origin_domains: list[str] = field(default_factory=list)
    sample_invalidation_distribution_ids: list[str] = field(default_factory=list)
    sample_price_classes: list[str] = field(default_factory=list)
    sample_logging_buckets: list[str] = field(default_factory=list)
    sample_cache_policy_ids: list[str] = field(default_factory=list)
    sample_origin_request_policy_ids: list[str] = field(default_factory=list)
    sample_viewer_protocol_policies: list[str] = field(default_factory=list)
    sample_origin_protocol_policies: list[str] = field(default_factory=list)
    invalidation_collection_errors: list[str] = field(default_factory=list)
    tag_collection_errors: list[str] = field(default_factory=list)
    metric_collection_status: str = "not_requested"
    metric_collection_reason: str = "CloudFront metric enrichment was not requested."
    metric_distribution_count: int = 0
    metric_datapoint_count: int = 0
    request_sum: int = 0
    bytes_downloaded_sum: int = 0
    bytes_uploaded_sum: int = 0
    four_xx_error_rate_average: float | None = None
    five_xx_error_rate_average: float | None = None
    metric_collection_errors: list[str] = field(default_factory=list)
    collection_evidence_version: int = 0
    behavior_histogram: CloudFrontBehaviorHistogram | None = None
    invalidation_path_evidence_complete: bool = True
    invalidation_collection_limited: bool = False
    tag_evidence_complete: bool = True
