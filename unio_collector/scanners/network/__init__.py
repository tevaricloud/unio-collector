from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "NETWORK_SCANNER_PACKS": ("unio_collector.scanners.network.packs", "NETWORK_SCANNER_PACKS"),
    "NETWORK_SCANNER_TYPES": ("unio_collector.scanners.network.packs", "NETWORK_SCANNER_TYPES"),
    "CloudFrontAlbOriginProtectionEvidence": ("unio_collector.scanners.network.cloudfront_alb_protection", "CloudFrontAlbOriginProtectionEvidence"),
    "CloudFrontAlbOriginProtectionReview": ("unio_collector.scanners.network.cloudfront_alb_protection", "CloudFrontAlbOriginProtectionReview"),
    "CloudFrontAlbOriginProtectionReviewRecord": ("unio_collector.scanners.network.cloudfront_alb_protection", "CloudFrontAlbOriginProtectionReviewRecord"),
    "CloudFrontAlbOriginProtectionReviewScanner": ("unio_collector.scanners.network.cloudfront_alb_protection", "CloudFrontAlbOriginProtectionReviewScanner"),
    "CloudFrontAlbOriginRecord": ("unio_collector.scanners.network.cloudfront_alb_protection", "CloudFrontAlbOriginRecord"),
    "CloudFrontOriginCostReviewEvidence": ("unio_collector.scanners.network.cloudfront_origin.evidence", "CloudFrontOriginCostReviewEvidence"),
    "CloudFrontOriginCostReviewScanner": ("unio_collector.scanners.network.cloudfront_origin.scanner", "CloudFrontOriginCostReviewScanner"),
    "NetworkPrivateLinkCostReviewScanner": ("unio_collector.scanners.network.privatelink.scanner", "NetworkPrivateLinkCostReviewScanner"),
    "NetworkPublicIpv4ReviewScanner": ("unio_collector.scanners.network.public_ipv4.scanner", "NetworkPublicIpv4ReviewScanner"),
    "NetworkTransitGatewayCostReviewScanner": ("unio_collector.scanners.network.transit_gateway.scanner", "NetworkTransitGatewayCostReviewScanner"),
    "NetworkVpcEndpointOpportunityReviewScanner": ("unio_collector.scanners.network.vpc_endpoint.scanner", "NetworkVpcEndpointOpportunityReviewScanner"),
    "PrivateLinkCostReviewEvidence": ("unio_collector.scanners.network.privatelink.evidence", "PrivateLinkCostReviewEvidence"),
    "PublicIpv4Evidence": ("unio_collector.scanners.network.public_ipv4.evidence", "PublicIpv4Evidence"),
    "TransitGatewayCostReviewEvidence": ("unio_collector.scanners.network.transit_gateway.evidence", "TransitGatewayCostReviewEvidence"),
    "VpcEndpointOpportunityEvidence": ("unio_collector.scanners.network.vpc_endpoint.evidence", "VpcEndpointOpportunityEvidence"),
    "VpcFlowLogAttributionEvidence": ("unio_collector.scanners.network.vpc_flow.attribution.evidence", "VpcFlowLogAttributionEvidence"),
    "VpcFlowLogAttributionScanner": ("unio_collector.scanners.network.vpc_flow.attribution.scanner", "VpcFlowLogAttributionScanner"),
    "VpcFlowLogCollector": ("unio_collector.aws.flow.collector", "VpcFlowLogCollector"),
    "VpcFlowQueryOptions": ("unio_collector.scanners.network.vpc_flow.query_options", "VpcFlowQueryOptions"),
    "build_cloudfront_execution_detail_note": ("unio_collector.scanners.network.cloudfront_origin.helpers", "build_cloudfront_execution_detail_note"),
    "build_flow_log_correlated_finding_update": ("unio_collector.scanners.network.vpc_flow.helpers", "build_flow_log_correlated_finding_update"),
    "build_vpc_flow_billing_correlation": ("unio_collector.scanners.network.vpc_flow.helpers", "build_vpc_flow_billing_correlation"),
    "correlate_flow_log_attribution_with_billing_findings": (
        "unio_collector.scanners.network.vpc_flow.helpers",
        "correlate_flow_log_attribution_with_billing_findings",
    ),
    "count_nat_path_candidates": ("unio_collector.scanners.network.vpc_flow.helpers", "count_nat_path_candidates"),
    "format_cloudfront_metric_collection_status": ("unio_collector.scanners.network.cloudfront_origin.helpers", "format_cloudfront_metric_collection_status"),
}

__all__ = (
    "NETWORK_SCANNER_PACKS",
    "NETWORK_SCANNER_TYPES",
    "CloudFrontAlbOriginProtectionEvidence",
    "CloudFrontAlbOriginProtectionReview",
    "CloudFrontAlbOriginProtectionReviewRecord",
    "CloudFrontAlbOriginProtectionReviewScanner",
    "CloudFrontAlbOriginRecord",
    "CloudFrontOriginCostReviewEvidence",
    "CloudFrontOriginCostReviewScanner",
    "NetworkPrivateLinkCostReviewScanner",
    "NetworkPublicIpv4ReviewScanner",
    "NetworkTransitGatewayCostReviewScanner",
    "NetworkVpcEndpointOpportunityReviewScanner",
    "PrivateLinkCostReviewEvidence",
    "PublicIpv4Evidence",
    "TransitGatewayCostReviewEvidence",
    "VpcEndpointOpportunityEvidence",
    "VpcFlowLogAttributionEvidence",
    "VpcFlowLogAttributionScanner",
    "VpcFlowLogCollector",
    "VpcFlowQueryOptions",
    "build_cloudfront_execution_detail_note",
    "build_flow_log_correlated_finding_update",
    "build_vpc_flow_billing_correlation",
    "correlate_flow_log_attribution_with_billing_findings",
    "count_nat_path_candidates",
    "format_cloudfront_metric_collection_status",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
