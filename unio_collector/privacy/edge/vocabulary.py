"""Only fixed producer/control positions may preserve finite edge metadata."""

ALB_LITERALS = {
    "cloudfront_origins[].source_restriction": {"", "origin_access_control", "cloudfront_vpc_origin"},
    "cloudfront_origins[].origin_kind": {"custom", "vpc"},
    "cloudfront_origins[].host_forwarding_state": {"origin_domain", "viewer_host_possible", "unknown"},
    "header_verifications[].match_state": {"matched", "not_matched", "control_present", "unknown"},
    "coverage[].evidence_type": {"cloudfront_origins", "vpc_origin_detail", "origin_request_policy", "listener_rules", "managed_prefix_lists"},
    "coverage[].status": {"collected", "unavailable", "not_applicable", "legacy_unknown"},
    "security_group_rules[].source_type": {"cidr", "prefix_list", "security_group"},
    "security_group_rules[].source_control_verification": {"legacy_unverified", "verified", "unverified"},
}
PROTOCOLS = {"", "http-only", "https-only", "match-viewer"}
PRESERVED = {
    "cloudfront_origins[].origin_protocol_policy": PROTOCOLS,
    "vpc_origins[].origin_protocol_policy": PROTOCOLS,
    "load_balancers[].scheme": {"internet-facing", "internal"},
    "load_balancers[].load_balancer_type": {"application"},
    "listeners[].protocol": {"HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"},
    "listeners[].default_action_types[]": {"forward", "fixed-response", "redirect", "authenticate-cognito", "authenticate-oidc"},
    "listener_rules[].action_types[]": {"forward", "fixed-response", "redirect", "authenticate-cognito", "authenticate-oidc"},
    "vpc_origins[].status": {"Deployed", "InProgress", "Deploying", "Failed"},
    "waf_associations[].resource_type": {"CloudFront distribution", "Application Load Balancer"},
    "security_group_rules[].protocol": {"tcp", "udp", "icmp", "icmpv6", "-1", *(str(number) for number in range(256))},
    "records[].sample_price_classes[]": {"PriceClass_All", "PriceClass_100", "PriceClass_200"},
    "records[].sample_viewer_protocol_policies[]": {"allow-all", "redirect-to-https", "https-only"},
    "records[].sample_origin_protocol_policies[]": PROTOCOLS - {""},
    "records[].metric_collection_status": {
        "not_requested",
        "skipped_by_chargeable_policy",
        "not_configured",
        "not_applicable",
        "no_datapoints",
        "failed",
        "collected",
    },
}
