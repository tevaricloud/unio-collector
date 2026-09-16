from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CONDITIONAL_ACTION_CONDITION = "selected scanner path or resource detail requires this action"
OPTIONAL_ENRICHMENT_CONDITION = "optional metric enrichment is enabled and source metric evidence is available"

S3_INCOMPLETE_MULTIPART_REVIEW_EVIDENCE = (
    "S3 bucket",
    "Incomplete multipart upload",
)

S3_LIFECYCLE_COST_REVIEW_EVIDENCE = ("S3 bucket",)

S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE = (
    "S3 bucket",
    "S3 replication rule",
)

STORAGE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "s3-incomplete-multipart-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "S3 incomplete multipart upload review requires s3:ListAllMyBuckets to collect read-only S3 bucket, Incomplete multipart upload evidence.",
                chargeable=False,
                evidence_categories=S3_INCOMPLETE_MULTIPART_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:ListBucketMultipartUploads",
                "required",
                "S3 incomplete multipart upload review requires s3:ListBucketMultipartUploads to collect "
                "read-only S3 bucket, Incomplete multipart upload evidence.",
                chargeable=False,
                evidence_categories=S3_INCOMPLETE_MULTIPART_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListBucketMultipartUploads is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketLocation",
                "conditional",
                "S3 incomplete multipart upload review uses s3:GetBucketLocation when selected S3 bucket, Incomplete "
                "multipart upload evidence paths require it.",
                chargeable=False,
                evidence_categories=S3_INCOMPLETE_MULTIPART_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketLocation is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=CONDITIONAL_ACTION_CONDITION,
            ),
        ),
    ),
    "s3-lifecycle-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "S3 lifecycle cost review requires s3:ListAllMyBuckets to collect read-only S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetLifecycleConfiguration",
                "required",
                "S3 lifecycle cost review requires s3:GetLifecycleConfiguration to collect read-only S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetLifecycleConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketVersioning",
                "required",
                "S3 lifecycle cost review requires s3:GetBucketVersioning to collect read-only S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketVersioning is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetReplicationConfiguration",
                "required",
                "S3 lifecycle cost review requires s3:GetReplicationConfiguration to collect read-only S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetReplicationConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketTagging",
                "required",
                "S3 lifecycle cost review requires s3:GetBucketTagging to collect read-only S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketTagging is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketLocation",
                "conditional",
                "S3 lifecycle cost review uses s3:GetBucketLocation when selected S3 bucket evidence paths require it.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketLocation is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=CONDITIONAL_ACTION_CONDITION,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "optional_enrichment",
                "S3 lifecycle cost review uses cloudwatch:GetMetricData for optional enrichment of S3 bucket evidence.",
                chargeable=False,
                evidence_categories=S3_LIFECYCLE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=OPTIONAL_ENRICHMENT_CONDITION,
            ),
        ),
    ),
    "s3-versioning-and-replication-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "S3 versioning and replication review requires s3:ListAllMyBuckets to collect read-only S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketVersioning",
                "required",
                "S3 versioning and replication review requires s3:GetBucketVersioning to collect read-only S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketVersioning is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetReplicationConfiguration",
                "required",
                "S3 versioning and replication review requires s3:GetReplicationConfiguration to collect read-only S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetReplicationConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetLifecycleConfiguration",
                "required",
                "S3 versioning and replication review requires s3:GetLifecycleConfiguration to collect read-only S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetLifecycleConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketTagging",
                "required",
                "S3 versioning and replication review requires s3:GetBucketTagging to collect read-only S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketTagging is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketLocation",
                "conditional",
                "S3 versioning and replication review uses s3:GetBucketLocation when selected S3 bucket, S3 replication rule evidence paths require it.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketLocation is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=CONDITIONAL_ACTION_CONDITION,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "optional_enrichment",
                "S3 versioning and replication review uses cloudwatch:GetMetricData for optional enrichment of S3 bucket, S3 replication rule evidence.",
                chargeable=False,
                evidence_categories=S3_VERSIONING_AND_REPLICATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=OPTIONAL_ENRICHMENT_CONDITION,
            ),
        ),
    ),
}
