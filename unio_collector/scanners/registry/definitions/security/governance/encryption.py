from __future__ import annotations  # noqa: D100

from unio_collector.scanners.scanner.definition import ScannerDefinition

SECURITY_GOVERNANCE_ENCRYPTION_SCANNERS: dict[str, ScannerDefinition] = {
    "encryption-baseline-review": ScannerDefinition(
        scanner_id="encryption-baseline-review",
        display_name="Encryption baseline review",
        description=(
            "Reviews EBS encryption-by-default settings, visible EBS volume and "
            "snapshot encryption state, and S3 bucket default encryption as "
            "reusable storage encryption governance evidence."
        ),
        aws_services=("Amazon EBS", "Amazon EC2", "Amazon S3"),
        resource_types=(
            "EBS regional encryption setting",
            "EBS volume",
            "EBS snapshot",
            "S3 bucket",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:GetEbsEncryptionByDefault",
            "ec2:GetEbsDefaultKmsKeyId",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots",
            "s3:ListAllMyBuckets",
            "s3:GetEncryptionConfiguration",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:GetEbsEncryptionByDefault",
            "ec2:GetEbsDefaultKmsKeyId",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots",
            "s3:ListBuckets",
            "s3:GetBucketEncryption",
        ),
        risk_level="high",
        output_finding_types=(
            "ebs_encryption_by_default_gap",
            "ebs_unencrypted_volume",
            "ebs_unencrypted_snapshot",
            "s3_bucket_encryption_configuration_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not inspect object contents, application-layer encryption, database encryption settings, or every managed service storage surface.",
            "Encryption remediation can require replacement or migration work and must be planned with workload owners before changes.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized encryption baseline evidence and uses scanner metadata for deterministic finding ownership."),
    ),
    "kms-key-posture-review": ScannerDefinition(
        scanner_id="kms-key-posture-review",
        display_name="KMS key posture review",
        description=("Reviews customer-managed KMS key state and automatic rotation status as reusable encryption governance evidence."),
        aws_services=("AWS Key Management Service",),
        resource_types=("KMS key",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
        ),
        risk_level="medium",
        output_finding_types=(
            "kms_key_rotation_disabled",
            "kms_customer_key_disabled",
            "kms_customer_key_pending_deletion",
        ),
        maturity="experimental",
        limitations=(
            "Does not inspect every key policy, grant, alias, or consuming workload.",
            "Disabled or pending-deletion keys can be intentional; key owner and data owner validation is required before any change.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized KMS key posture evidence and uses scanner metadata for deterministic finding ownership."),
    ),
}

__all__ = ["SECURITY_GOVERNANCE_ENCRYPTION_SCANNERS"]
