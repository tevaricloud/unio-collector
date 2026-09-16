from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "AlbOriginListenerRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.evidence", "AlbOriginListenerRecord"),
    "AlbOriginListenerRuleRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.listener.rule_record", "AlbOriginListenerRuleRecord"),
    "AlbOriginLoadBalancerRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.evidence", "AlbOriginLoadBalancerRecord"),
    "AlbOriginSecurityGroupRuleRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.security_group", "AlbOriginSecurityGroupRuleRecord"),
    "AlbOriginWafAssociationRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.evidence", "AlbOriginWafAssociationRecord"),
    "CloudFrontAlbOriginProtectionEvidence": ("unio_collector.scanners.network.cloudfront_alb_protection.evidence", "CloudFrontAlbOriginProtectionEvidence"),
    "CloudFrontAlbOriginProtectionReview": ("unio_collector.scanners.network.cloudfront_alb_protection.analyzer", "CloudFrontAlbOriginProtectionReview"),
    "CloudFrontAlbOriginProtectionReviewRecord": (
        "unio_collector.scanners.network.cloudfront_alb_protection.review_record",
        "CloudFrontAlbOriginProtectionReviewRecord",
    ),
    "CloudFrontAlbOriginProtectionReviewScanner": (
        "unio_collector.scanners.network.cloudfront_alb_protection.scanner",
        "CloudFrontAlbOriginProtectionReviewScanner",
    ),
    "CloudFrontAlbOriginProtectionStatus": ("unio_collector.scanners.network.cloudfront_alb_protection.status", "CloudFrontAlbOriginProtectionStatus"),
    "CloudFrontAlbOriginRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.evidence", "CloudFrontAlbOriginRecord"),
    "CloudFrontVpcOriginRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.vpc_origin_record", "CloudFrontVpcOriginRecord"),
    "OriginHeaderVerificationRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.header", "OriginHeaderVerificationRecord"),
    "OriginHeaderVerifier": ("unio_collector.scanners.network.cloudfront_alb_protection.header", "OriginHeaderVerifier"),
    "OriginProtectionCoverageRecord": ("unio_collector.scanners.network.cloudfront_alb_protection.coverage_record", "OriginProtectionCoverageRecord"),
}

__all__ = (
    "AlbOriginListenerRecord",
    "AlbOriginListenerRuleRecord",
    "AlbOriginLoadBalancerRecord",
    "AlbOriginSecurityGroupRuleRecord",
    "AlbOriginWafAssociationRecord",
    "CloudFrontAlbOriginProtectionEvidence",
    "CloudFrontAlbOriginProtectionReview",
    "CloudFrontAlbOriginProtectionReviewRecord",
    "CloudFrontAlbOriginProtectionReviewScanner",
    "CloudFrontAlbOriginProtectionStatus",
    "CloudFrontAlbOriginRecord",
    "CloudFrontVpcOriginRecord",
    "OriginHeaderVerificationRecord",
    "OriginHeaderVerifier",
    "OriginProtectionCoverageRecord",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
