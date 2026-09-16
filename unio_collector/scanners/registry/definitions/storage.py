from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

STORAGE_SCANNERS: dict[str, ScannerDefinition] = {
    "s3-lifecycle-cost-review": ScannerDefinition(
        scanner_id="s3-lifecycle-cost-review",
        display_name="S3 lifecycle cost review",
        description=("Reviews S3 bucket lifecycle, versioning, and replication metadata for storage growth and retention governance signals."),
        aws_services=("Amazon S3",),
        resource_types=("S3 bucket",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "s3:ListAllMyBuckets",
            "s3:GetLifecycleConfiguration",
            "s3:GetBucketVersioning",
            "s3:GetReplicationConfiguration",
            "s3:GetBucketTagging",
        ),
        conditional_iam_actions=(
            "s3:GetBucketLocation",
            "cloudwatch:GetMetricData",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "s3:ListBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketLifecycleConfiguration",
            "s3:GetBucketVersioning",
            "s3:GetBucketReplication",
            "s3:GetBucketTagging",
            "cloudwatch:GetMetricData",
        ),
        risk_level="medium",
        output_finding_types=("s3_lifecycle_missing_policy",),
        maturity="experimental",
        limitations=(
            "Does not inspect every object or object-level access pattern.",
            "Does not estimate exact S3 savings without storage-class and object-age evidence.",
            "Does not create, update, or remove lifecycle or replication rules.",
            (
                "Optional tag and replication metadata can be skipped through "
                "collection_profile or explicit collection toggles; skipped "
                "metadata is reported as a configuration limit."
            ),
            ("Development lifecycle_detail_mode retains a neutral stable operational detail cap; capped evidence is reported as incomplete."),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects S3 lifecycle records with cost context during collection and analyzes only serialized lifecycle evidence without AWS clients."
        ),
    ),
    "s3-versioning-and-replication-review": ScannerDefinition(
        scanner_id="s3-versioning-and-replication-review",
        display_name="S3 versioning and replication review",
        description=(
            "Reviews S3 versioning, noncurrent version lifecycle controls, "
            "and replication metadata for storage growth and cross-region "
            "cost-governance signals."
        ),
        aws_services=("Amazon S3",),
        resource_types=("S3 bucket", "S3 replication rule"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "s3:ListAllMyBuckets",
            "s3:GetBucketVersioning",
            "s3:GetReplicationConfiguration",
            "s3:GetLifecycleConfiguration",
            "s3:GetBucketTagging",
        ),
        conditional_iam_actions=(
            "s3:GetBucketLocation",
            "cloudwatch:GetMetricData",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "s3:ListBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketVersioning",
            "s3:GetBucketReplication",
            "s3:GetBucketLifecycleConfiguration",
            "s3:GetBucketTagging",
            "cloudwatch:GetMetricData",
        ),
        risk_level="medium",
        output_finding_types=(
            "s3_versioning_without_noncurrent_expiry",
            "s3_replication_cost_review",
        ),
        maturity="experimental",
        execution_phase="dependent",
        depends_on_scanner_ids=("s3-lifecycle-cost-review",),
        limitations=(
            "Does not inspect every object or noncurrent object age distribution.",
            "Does not estimate exact S3 savings without storage-class and object-age evidence.",
            "Does not create, update, remove, or disable versioning, lifecycle, or replication rules.",
            "Replication suitability requires resilience, compliance, and data-owner validation.",
            ("Development lifecycle_detail_mode retains a neutral stable operational detail cap; capped evidence is reported as incomplete."),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects S3 versioning, replication, lifecycle, tag, and cost-context "
            "records during collection and analyzes only serialized lifecycle "
            "evidence without AWS clients."
        ),
    ),
    "s3-incomplete-multipart-review": ScannerDefinition(
        scanner_id="s3-incomplete-multipart-review",
        display_name="S3 incomplete multipart upload review",
        description=("Checks for incomplete multipart uploads that can leave billable parts stored until completed or aborted."),
        aws_services=("Amazon S3",),
        resource_types=("S3 bucket", "Incomplete multipart upload"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "s3:ListAllMyBuckets",
            "s3:ListBucketMultipartUploads",
        ),
        conditional_iam_actions=("s3:GetBucketLocation",),
        required_permission_level="read_only",
        aws_api_calls=(
            "s3:ListBuckets",
            "s3:GetBucketLocation",
            "s3:ListMultipartUploads",
        ),
        risk_level="medium",
        output_finding_types=("s3_incomplete_multipart_uploads",),
        maturity="experimental",
        execution_phase="dependent",
        depends_on_scanner_ids=("s3-lifecycle-cost-review",),
        limitations=(
            "Does not abort multipart uploads.",
            "Does not know whether an upload is intentionally still active.",
            "Does not estimate storage cost without object-part size evidence.",
            (
                "The analyzer can suppress findings for buckets whose visible "
                "lifecycle rules already abort incomplete multipart uploads; "
                "this compatibility policy does not suppress collection."
            ),
            "max_multipart_buckets is a neutral name-ordered operational cap for development runs; configure 0 for full coverage.",
            ("multipart_bucket_selection_mode remains accepted for analyzer compatibility but does not change collector bucket selection."),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects incomplete multipart upload records with S3 cost context "
            "during collection and analyzes only serialized multipart evidence "
            "without AWS clients."
        ),
    ),
}

STORAGE_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "storage",
    STORAGE_SCANNERS,
)
