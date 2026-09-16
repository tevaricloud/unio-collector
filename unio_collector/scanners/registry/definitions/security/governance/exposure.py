from __future__ import annotations  # noqa: D100

from unio_collector.scanners.scanner.definition import ScannerDefinition

SECURITY_GOVERNANCE_EXPOSURE_SCANNERS: dict[str, ScannerDefinition] = {
    "ec2-security-group-exposure-review": ScannerDefinition(
        scanner_id="ec2-security-group-exposure-review",
        display_name="EC2 security group exposure review",
        description=("Reviews EC2 security group ingress rules for public IPv4 or IPv6 access to sensitive service and administration ports."),
        aws_services=("Amazon EC2", "Amazon VPC"),
        resource_types=("EC2 security group", "Security group ingress rule"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=("ec2:DescribeRegions", "ec2:DescribeSecurityGroups"),
        required_permission_level="read_only",
        aws_api_calls=("ec2:DescribeRegions", "ec2:DescribeSecurityGroups"),
        risk_level="high",
        output_finding_types=("security_group_public_ingress",),
        maturity="experimental",
        limitations=(
            "Does not inspect host firewall rules, network ACL intent, DNS, application authentication, or approved source allow-lists.",
            "Public ingress can be intentional; business justification and owner validation remain required.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized security group exposure evidence and uses scanner metadata for deterministic finding ownership."
        ),
    ),
    "s3-public-access-security-review": ScannerDefinition(
        scanner_id="s3-public-access-security-review",
        display_name="S3 public access security review",
        description=(
            "Reviews S3 account public access block, bucket public access block, "
            "bucket policy public status, and bucket ACL public grants as "
            "reusable storage security governance evidence."
        ),
        aws_services=("Amazon S3", "Amazon S3 Control"),
        resource_types=(
            "S3 account public access block",
            "S3 bucket",
            "S3 bucket policy status",
            "S3 bucket ACL",
        ),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=(
            "s3:ListAllMyBuckets",
            "s3:GetPublicAccessBlock",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketAcl",
            "s3control:GetPublicAccessBlock",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "s3:ListBuckets",
            "s3:GetPublicAccessBlock",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketAcl",
            "s3control:GetPublicAccessBlock",
        ),
        risk_level="high",
        output_finding_types=(
            "s3_public_access_block_gap",
            "s3_bucket_public_access_gap",
        ),
        maturity="experimental",
        limitations=(
            "Does not read S3 objects or inspect object-level ACLs.",
            "Public access status may be affected by missing bucket-level permissions and requires data-owner validation before changes.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized S3 public access evidence with account identity carried in evidence."),
    ),
    "public-service-exposure-review": ScannerDefinition(
        scanner_id="public-service-exposure-review",
        display_name="Public service exposure review",
        description=(
            "Reviews public endpoint exposure signals for RDS, OpenSearch, "
            "Redshift, internet-facing load balancers, API Gateway, and "
            "CloudFront origins using read-only service metadata."
        ),
        aws_services=(
            "Amazon RDS",
            "Amazon OpenSearch Service",
            "Amazon Redshift",
            "Elastic Load Balancing",
            "Amazon API Gateway",
            "Amazon CloudFront",
        ),
        resource_types=(
            "RDS DB instance",
            "OpenSearch domain",
            "Redshift cluster",
            "Application or Network Load Balancer",
            "API Gateway API",
            "CloudFront origin",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "rds:DescribeDBInstances",
            "es:ListDomainNames",
            "es:DescribeDomainConfig",
            "redshift:DescribeClusters",
            "elasticloadbalancing:DescribeLoadBalancers",
            "apigateway:GET",
            "apigatewayv2:GetApis",
            "cloudfront:ListDistributions",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "rds:DescribeDBInstances",
            "es:ListDomainNames",
            "es:DescribeDomainConfig",
            "redshift:DescribeClusters",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elbv2:DescribeLoadBalancers",
            "apigateway:GetRestApis",
            "apigatewayv2:GetApis",
            "cloudfront:ListDistributions",
        ),
        risk_level="high",
        output_finding_types=(
            "rds_publicly_accessible_instance",
            "opensearch_public_endpoint_review",
            "redshift_publicly_accessible_cluster",
            "load_balancer_internet_facing_review",
            "api_gateway_public_endpoint_review",
            "cloudfront_origin_exposure_review",
        ),
        maturity="experimental",
        limitations=(
            "Public endpoint evidence does not prove exposure is unapproved, exploitable, or missing application-layer controls.",
            "CloudFront origin records require validation of origin access controls, WAF, resource policies, and intended public paths.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized public service exposure evidence; summary side-channel writes are optional during strict replay."
        ),
    ),
    "ecr-image-scan-posture-review": ScannerDefinition(
        scanner_id="ecr-image-scan-posture-review",
        display_name="ECR image scan posture review",
        description=("Reviews ECR repository scan-on-push, image tag mutability, and registry scanning configuration as container image governance evidence."),
        aws_services=("Amazon Elastic Container Registry",),
        resource_types=(
            "ECR repository",
            "ECR registry scanning configuration",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ecr:DescribeRepositories",
            "ecr:GetRegistryScanningConfiguration",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ecr:DescribeRepositories",
            "ecr:GetRegistryScanningConfiguration",
        ),
        risk_level="medium",
        output_finding_types=(
            "ecr_registry_scanning_configuration_review",
            "ecr_repository_scan_on_push_disabled",
            "ecr_repository_mutable_tags_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not pull images, inspect image contents, or prove vulnerabilities are absent.",
            "Alternative CI/CD or third-party image scanning controls must be validated separately with platform owners.",
            "Mutable tags can be intentional for some workflows and should be reviewed against release and rollback practices before changes.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized ECR image scan posture evidence with "
            "account identity carried in evidence; summary side-channel writes "
            "are optional during strict replay."
        ),
    ),
}

__all__ = ["SECURITY_GOVERNANCE_EXPOSURE_SCANNERS"]
