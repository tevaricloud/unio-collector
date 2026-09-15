from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

EC2_SECURITY_GROUP_EXPOSURE_REVIEW_EVIDENCE = (
    "EC2 security group",
    "Security group ingress rule",
)

ECR_IMAGE_SCAN_POSTURE_REVIEW_EVIDENCE = (
    "ECR repository",
    "ECR registry scanning configuration",
)

ENCRYPTION_BASELINE_REVIEW_EVIDENCE = (
    "EBS regional encryption setting",
    "EBS volume",
    "EBS snapshot",
    "S3 bucket",
)

PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE = (
    "RDS DB instance",
    "OpenSearch domain",
    "Redshift cluster",
    "Application or Network Load Balancer",
    "API Gateway API",
    "CloudFront origin",
)

S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE = (
    "S3 account public access block",
    "S3 bucket",
    "S3 bucket policy status",
    "S3 bucket ACL",
)

SECURITYHUB_CONTROL_SUMMARY_REVIEW_EVIDENCE = (
    "Security Hub control",
    "Security Hub active failed finding",
)

SECURITY_RESOURCE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "ec2-security-group-exposure-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "EC2 security group exposure review requires ec2:DescribeRegions to collect read-only EC2 security group, "
                "Security group ingress rule evidence.",
                chargeable=False,
                evidence_categories=EC2_SECURITY_GROUP_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSecurityGroups",
                "required",
                "EC2 security group exposure review requires ec2:DescribeSecurityGroups to collect read-only EC2 "
                "security group, Security group ingress rule evidence.",
                chargeable=False,
                evidence_categories=EC2_SECURITY_GROUP_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSecurityGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "ecr-image-scan-posture-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "ECR image scan posture review requires ec2:DescribeRegions to collect read-only ECR repository, ECR registry scanning configuration evidence.",
                chargeable=False,
                evidence_categories=ECR_IMAGE_SCAN_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecr:DescribeRepositories",
                "required",
                "ECR image scan posture review requires ecr:DescribeRepositories to collect read-only ECR "
                "repository, ECR registry scanning configuration evidence.",
                chargeable=False,
                evidence_categories=ECR_IMAGE_SCAN_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecr:DescribeRepositories is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecr:GetRegistryScanningConfiguration",
                "required",
                "ECR image scan posture review requires ecr:GetRegistryScanningConfiguration to collect "
                "read-only ECR repository, ECR registry scanning configuration evidence.",
                chargeable=False,
                evidence_categories=ECR_IMAGE_SCAN_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecr:GetRegistryScanningConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "encryption-baseline-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Encryption baseline review requires ec2:DescribeRegions to collect read-only EBS regional encryption "
                "setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:GetEbsEncryptionByDefault",
                "required",
                "Encryption baseline review requires ec2:GetEbsEncryptionByDefault to collect read-only EBS "
                "regional encryption setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:GetEbsEncryptionByDefault is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:GetEbsDefaultKmsKeyId",
                "required",
                "Encryption baseline review requires ec2:GetEbsDefaultKmsKeyId to collect read-only EBS regional "
                "encryption setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:GetEbsDefaultKmsKeyId is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVolumes",
                "required",
                "Encryption baseline review requires ec2:DescribeVolumes to collect read-only EBS regional encryption "
                "setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVolumes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSnapshots",
                "required",
                "Encryption baseline review requires ec2:DescribeSnapshots to collect read-only EBS regional encryption "
                "setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSnapshots is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "Encryption baseline review requires s3:ListAllMyBuckets to collect read-only EBS regional encryption "
                "setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetEncryptionConfiguration",
                "required",
                "Encryption baseline review requires s3:GetEncryptionConfiguration to collect read-only EBS "
                "regional encryption setting, EBS volume, EBS snapshot, S3 bucket evidence.",
                chargeable=False,
                evidence_categories=ENCRYPTION_BASELINE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetEncryptionConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "public-service-exposure-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Public service exposure review requires ec2:DescribeRegions to collect read-only RDS DB instance, "
                "OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway API, CloudFront "
                "origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "rds:DescribeDBInstances",
                "required",
                "Public service exposure review requires rds:DescribeDBInstances to collect read-only RDS DB "
                "instance, OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway "
                "API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:DescribeDBInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "es:ListDomainNames",
                "required",
                "Public service exposure review requires es:ListDomainNames to collect read-only RDS DB instance, "
                "OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway API, CloudFront "
                "origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="es:ListDomainNames is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "es:DescribeDomainConfig",
                "required",
                "Public service exposure review requires es:DescribeDomainConfig to collect read-only RDS DB "
                "instance, OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway "
                "API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="es:DescribeDomainConfig is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "redshift:DescribeClusters",
                "required",
                "Public service exposure review requires redshift:DescribeClusters to collect read-only RDS DB "
                "instance, OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway "
                "API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="redshift:DescribeClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeLoadBalancers",
                "required",
                "Public service exposure review requires "
                "elasticloadbalancing:DescribeLoadBalancers to collect read-only RDS DB instance, "
                "OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API "
                "Gateway API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "apigateway:GET",
                "required",
                "Public service exposure review requires apigateway:GET to collect read-only RDS DB instance, OpenSearch "
                "domain, Redshift cluster, Application or Network Load Balancer, API Gateway API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="apigateway:GET is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "apigatewayv2:GetApis",
                "required",
                "Public service exposure review requires apigatewayv2:GetApis to collect read-only RDS DB instance, "
                "OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API Gateway API, CloudFront "
                "origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="apigatewayv2:GetApis is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudfront:ListDistributions",
                "required",
                "Public service exposure review requires cloudfront:ListDistributions to collect read-only RDS "
                "DB instance, OpenSearch domain, Redshift cluster, Application or Network Load Balancer, API "
                "Gateway API, CloudFront origin evidence.",
                chargeable=False,
                evidence_categories=PUBLIC_SERVICE_EXPOSURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudfront:ListDistributions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "s3-public-access-security-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "S3 public access security review requires s3:ListAllMyBuckets to collect read-only S3 account public "
                "access block, S3 bucket, S3 bucket policy status, S3 bucket ACL evidence.",
                chargeable=False,
                evidence_categories=S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetPublicAccessBlock",
                "required",
                "S3 public access security review requires s3:GetPublicAccessBlock to collect read-only S3 account "
                "public access block, S3 bucket, S3 bucket policy status, S3 bucket ACL evidence.",
                chargeable=False,
                evidence_categories=S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetPublicAccessBlock is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketPolicyStatus",
                "required",
                "S3 public access security review requires s3:GetBucketPolicyStatus to collect read-only S3 account "
                "public access block, S3 bucket, S3 bucket policy status, S3 bucket ACL evidence.",
                chargeable=False,
                evidence_categories=S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketPolicyStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketAcl",
                "required",
                "S3 public access security review requires s3:GetBucketAcl to collect read-only S3 account public access "
                "block, S3 bucket, S3 bucket policy status, S3 bucket ACL evidence.",
                chargeable=False,
                evidence_categories=S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketAcl is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3control:GetPublicAccessBlock",
                "required",
                "S3 public access security review requires s3control:GetPublicAccessBlock to collect read-only "
                "S3 account public access block, S3 bucket, S3 bucket policy status, S3 bucket ACL evidence.",
                chargeable=False,
                evidence_categories=S3_PUBLIC_ACCESS_SECURITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3control:GetPublicAccessBlock is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "securityhub-control-summary-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Security Hub control summary review requires ec2:DescribeRegions to collect read-only Security Hub "
                "control, Security Hub active failed finding evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_CONTROL_SUMMARY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:DescribeHub",
                "required",
                "Security Hub control summary review requires securityhub:DescribeHub to collect read-only Security "
                "Hub control, Security Hub active failed finding evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_CONTROL_SUMMARY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:DescribeHub is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:GetFindings",
                "required",
                "Security Hub control summary review requires securityhub:GetFindings to collect read-only Security "
                "Hub control, Security Hub active failed finding evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_CONTROL_SUMMARY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:GetFindings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
