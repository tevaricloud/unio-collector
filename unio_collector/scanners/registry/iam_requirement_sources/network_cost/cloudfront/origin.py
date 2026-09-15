from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CLOUDFRONT_ORIGIN_COST_REVIEW_EVIDENCE = (
    "CloudFront distribution",
    "CloudFront origin",
    "Cache behavior",
    "CloudFront invalidation",
)

OPTIONAL_ENRICHMENT_CONDITION = "optional metric enrichment is enabled and source metric evidence is available"

CLOUDFRONT_ORIGIN_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "cloudfront-origin-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "cloudfront:ListDistributions",
                "required",
                "CloudFront origin cost review requires cloudfront:ListDistributions to collect read-only "
                "CloudFront distribution, CloudFront origin, Cache behavior, CloudFront invalidation evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ORIGIN_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudfront:ListDistributions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudfront:ListTagsForResource",
                "required",
                "CloudFront origin cost review requires cloudfront:ListTagsForResource to collect read-only "
                "CloudFront distribution, CloudFront origin, Cache behavior, CloudFront invalidation evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ORIGIN_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudfront:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudfront:ListInvalidations",
                "required",
                "CloudFront origin cost review requires cloudfront:ListInvalidations to collect read-only "
                "CloudFront distribution, CloudFront origin, Cache behavior, CloudFront invalidation evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ORIGIN_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudfront:ListInvalidations is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "optional_enrichment",
                "CloudFront origin cost review uses cloudwatch:GetMetricData for optional enrichment of "
                "CloudFront distribution, CloudFront origin, Cache behavior, CloudFront invalidation "
                "evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ORIGIN_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=OPTIONAL_ENRICHMENT_CONDITION,
            ),
        ),
    ),
}
