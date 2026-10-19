"""Explicit edge DTO fields: identities/text protect; operational facts retain meaning."""

from unio_collector.privacy.s3.fields import fields

ALB_COLLECTIONS = "cloudfront_origins load_balancers listeners listener_rules vpc_origins header_verifications coverage security_group_rules waf_associations"
ALB = {
    "": ("object", "safe_metadata", False),
    **fields("account_id", "string", "aws_account_id"),
    **fields("regions security_group_ids_collected limitations " + ALB_COLLECTIONS, "array"),
    **fields(" ".join(name + "[]" for name in ALB_COLLECTIONS.split()), "object"),
    **fields("regions[] load_balancers[].region listeners[].region security_group_rules[].region waf_associations[].region", "string", "region"),
    **fields("collection_time", "timestamp", "timestamp"),
    **fields(
        "limitations[] coverage[].limitation vpc_origins[].limitation waf_associations[].limitation security_group_rules[].source_description",
        "string",
        "free_text",
    ),
    **fields(
        (
            "security_group_ids_collected[] cloudfront_origins[].distribution_id cloudfront_origins[].origin_id "
            "cloudfront_origins[].web_acl_id cloudfront_origins[].vpc_origin_id load_balancers[].name "
            "load_balancers[].security_group_ids[] vpc_origins[].vpc_origin_id header_verifications[].distribution_id "
            "header_verifications[].origin_id header_verifications[].header_name security_group_rules[].group_id "
            "security_group_rules[].source_value security_group_rules[].source_control coverage[].scope_id "
            "waf_associations[].resource_id waf_associations[].web_acl_id"
        ),
        "string",
        "resource_id",
    ),
    **fields(
        (
            "cloudfront_origins[].distribution_arn load_balancers[].arn listeners[].load_balancer_arn "
            "listeners[].listener_arn listener_rules[].listener_arn vpc_origins[].endpoint_arn "
            "header_verifications[].listener_arn"
        ),
        "string",
        "arn",
    ),
    **fields("cloudfront_origins[].distribution_domain_name cloudfront_origins[].origin_domain_name load_balancers[].dns_name", "string", "resource_name"),
    **fields(
        (
            "cloudfront_origins[].origin_custom_header_names load_balancers[].security_group_ids "
            "listeners[].default_action_types listener_rules[].action_types listener_rules[].http_header_control_names"
        ),
        "array",
    ),
    **fields("cloudfront_origins[].origin_custom_header_names[] listener_rules[].http_header_control_names[]", "string", "resource_name"),
    **fields(
        (
            "cloudfront_origins[].enabled listeners[].default_deny listener_rules[].default_rule "
            "listener_rules[].default_deny listener_rules[].host_header_control_present "
            "listener_rules[].host_header_matches_origin header_verifications[].control_present "
            "header_verifications[].forward_action security_group_rules[].public waf_associations[].associated"
        ),
        "boolean",
    ),
    **fields(
        (
            "cloudfront_origins[].http_port cloudfront_origins[].https_port vpc_origins[].http_port "
            "vpc_origins[].https_port security_group_rules[].from_port security_group_rules[].to_port"
        ),
        "port",
        nullable=True,
    ),
    **fields("listeners[].port", "port"),
    **fields("security_group_rules[].cidr", "string", "cidr"),
    **fields(" ".join(name + "[].evidence_ref" for name in ALB_COLLECTIONS.split()), "string", "resource_id"),
    **fields(
        (
            "cloudfront_origins[].source_restriction cloudfront_origins[].origin_kind "
            "cloudfront_origins[].origin_protocol_policy cloudfront_origins[].host_forwarding_state "
            "load_balancers[].scheme load_balancers[].load_balancer_type listeners[].protocol "
            "listeners[].default_action_types[] listeners[].default_fixed_response_status listener_rules[].priority "
            "listener_rules[].action_types[] listener_rules[].fixed_response_status "
            "vpc_origins[].origin_protocol_policy vpc_origins[].status header_verifications[].rule_priority "
            "header_verifications[].match_state coverage[].evidence_type coverage[].status "
            "security_group_rules[].protocol security_group_rules[].source_type "
            "security_group_rules[].source_control_verification waf_associations[].resource_type"
        ),
        "string",
        "free_text",
    ),
}
COUNTS = (
    "distribution_count enabled_distribution_count disabled_distribution_count origin_count "
    "custom_origin_count s3_origin_count s3_rest_origin_count s3_website_origin_count "
    "aws_service_origin_count unknown_origin_count load_balancer_origin_count api_gateway_origin_count "
    "custom_domain_origin_count origin_shield_enabled_count cache_behavior_count ordered_cache_behavior_count "
    "price_class_all_count cache_policy_behavior_count origin_request_policy_behavior_count "
    "legacy_forwarded_values_behavior_count cache_fragmentation_behavior_count "
    "origin_request_expansion_behavior_count compression_disabled_behavior_count "
    "query_string_forwarding_behavior_count all_cookie_forwarding_behavior_count "
    "header_forwarding_behavior_count zero_ttl_behavior_count allow_all_viewer_protocol_policy_count "
    "redirect_to_https_viewer_protocol_policy_count https_only_viewer_protocol_policy_count "
    "all_methods_allowed_behavior_count http_only_origin_policy_count https_only_origin_policy_count "
    "match_viewer_origin_policy_count logging_enabled_count logging_bucket_count web_acl_associated_count "
    "tagged_distribution_count invalidation_distribution_count invalidation_batch_count "
    "invalidation_path_count wildcard_invalidation_path_count recent_invalidation_batch_count "
    "recent_invalidation_path_count recent_wildcard_invalidation_path_count metric_distribution_count "
    "metric_datapoint_count request_sum bytes_downloaded_sum bytes_uploaded_sum collection_evidence_version"
)
SAMPLES = (
    "sample_distribution_ids sample_distribution_domains sample_origin_domains "
    "sample_invalidation_distribution_ids sample_price_classes sample_logging_buckets sample_cache_policy_ids "
    "sample_origin_request_policy_ids sample_viewer_protocol_policies sample_origin_protocol_policies"
)
ERRORS = "invalidation_collection_errors tag_collection_errors metric_collection_errors"
COST = {
    "": ("object", "safe_metadata", False),
    **fields("records regions", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields(" ".join("records[]." + name for name in COUNTS.split()), "count", "summary_count"),
    **fields(" ".join("records[]." + name for name in (SAMPLES + " " + ERRORS).split()), "array"),
    **fields(" ".join("records[]." + name + "[]" for name in SAMPLES.split()), "string", "resource_id"),
    **fields(" ".join("records[]." + name + "[]" for name in ERRORS.split()), "string", "free_text"),
    **fields("records[].metric_collection_status records[].metric_collection_reason", "string", "free_text"),
    **fields(
        (
            "records[].invalidation_detail_collected records[].invalidation_path_evidence_complete "
            "records[].invalidation_collection_limited records[].tag_evidence_complete"
        ),
        "boolean",
    ),
    **fields("records[].four_xx_error_rate_average records[].five_xx_error_rate_average", "number", nullable=True),
    **fields("records[].behavior_histogram", "object", nullable=True),
    **fields("records[].behavior_histogram.counts", "array"),
    **fields("records[].behavior_histogram.counts[]", "count"),
}

COST["records[].price_class_all_count"] = ("count", "summary_count", False)
COST["records[].sample_price_classes"] = ("array", "cost", False)
