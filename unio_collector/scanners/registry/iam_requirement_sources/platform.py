from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

API_GATEWAY_COST_REVIEW_EVIDENCE = (
    "API Gateway API",
    "API Gateway stage",
)

ECS_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "ECS cluster",
    "ECS service",
)

EKS_COST_RISK_REVIEW_EVIDENCE = (
    "EKS cluster",
    "EKS managed node group",
    "Fargate profile",
)

ELASTICACHE_COST_REVIEW_EVIDENCE = (
    "ElastiCache cache cluster",
    "ElastiCache replication group",
    "Cache node",
)

OPENSEARCH_COST_REVIEW_EVIDENCE = (
    "OpenSearch domain",
    "OpenSearch node",
    "EBS volume",
)

REDSHIFT_COST_REVIEW_EVIDENCE = (
    "Redshift cluster",
    "Redshift Serverless namespace",
    "Redshift Serverless workgroup",
)

PLATFORM_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "api-gateway-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "API Gateway cost review requires ec2:DescribeRegions to collect read-only API Gateway API, API Gateway stage evidence.",
                chargeable=False,
                evidence_categories=API_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "apigateway:GET",
                "required",
                "API Gateway cost review requires apigateway:GET to collect read-only API Gateway API, API Gateway stage evidence.",
                chargeable=False,
                evidence_categories=API_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="apigateway:GET is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "API Gateway cost review requires ce:GetCostAndUsage to collect read-only API Gateway API, API Gateway stage evidence.",
                chargeable=False,
                evidence_categories=API_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "ecs-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "ECS cost governance review requires ec2:DescribeRegions to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecs:ListClusters",
                "required",
                "ECS cost governance review requires ecs:ListClusters to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecs:ListClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecs:DescribeClusters",
                "required",
                "ECS cost governance review requires ecs:DescribeClusters to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecs:DescribeClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecs:ListServices",
                "required",
                "ECS cost governance review requires ecs:ListServices to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecs:ListServices is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecs:DescribeServices",
                "required",
                "ECS cost governance review requires ecs:DescribeServices to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecs:DescribeServices is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ecs:DescribeTaskDefinition",
                "required",
                "ECS cost governance review requires ecs:DescribeTaskDefinition to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ecs:DescribeTaskDefinition is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "ECS cost governance review requires ce:GetCostAndUsage to collect read-only ECS cluster, ECS service evidence.",
                chargeable=False,
                evidence_categories=ECS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "eks-cost-risk-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "EKS cost risk review requires ec2:DescribeRegions to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:ListClusters",
                "required",
                "EKS cost risk review requires eks:ListClusters to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:ListClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:DescribeCluster",
                "required",
                "EKS cost risk review requires eks:DescribeCluster to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:DescribeCluster is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:ListNodegroups",
                "required",
                "EKS cost risk review requires eks:ListNodegroups to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:ListNodegroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:DescribeNodegroup",
                "required",
                "EKS cost risk review requires eks:DescribeNodegroup to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:DescribeNodegroup is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:ListFargateProfiles",
                "required",
                "EKS cost risk review requires eks:ListFargateProfiles to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:ListFargateProfiles is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:DescribeFargateProfile",
                "required",
                "EKS cost risk review requires eks:DescribeFargateProfile to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:DescribeFargateProfile is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "EKS cost risk review requires ce:GetCostAndUsage to collect read-only EKS cluster, EKS managed node group, Fargate profile evidence.",
                chargeable=False,
                evidence_categories=EKS_COST_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "elasticache-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "ElastiCache cost review requires ec2:DescribeRegions to collect read-only ElastiCache cache cluster, "
                "ElastiCache replication group, Cache node evidence.",
                chargeable=False,
                evidence_categories=ELASTICACHE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticache:DescribeCacheClusters",
                "required",
                "ElastiCache cost review requires elasticache:DescribeCacheClusters to collect read-only "
                "ElastiCache cache cluster, ElastiCache replication group, Cache node evidence.",
                chargeable=False,
                evidence_categories=ELASTICACHE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticache:DescribeCacheClusters is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticache:DescribeReplicationGroups",
                "required",
                "ElastiCache cost review requires elasticache:DescribeReplicationGroups to collect "
                "read-only ElastiCache cache cluster, ElastiCache replication group, Cache node "
                "evidence.",
                chargeable=False,
                evidence_categories=ELASTICACHE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticache:DescribeReplicationGroups is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "ElastiCache cost review requires cloudwatch:GetMetricData to collect read-only ElastiCache cache "
                "cluster, ElastiCache replication group, Cache node evidence.",
                chargeable=False,
                evidence_categories=ELASTICACHE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "ElastiCache cost review requires ce:GetCostAndUsage to collect read-only ElastiCache cache cluster, "
                "ElastiCache replication group, Cache node evidence.",
                chargeable=False,
                evidence_categories=ELASTICACHE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "opensearch-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "OpenSearch cost review requires ec2:DescribeRegions to collect read-only OpenSearch domain, OpenSearch node, EBS volume evidence.",
                chargeable=False,
                evidence_categories=OPENSEARCH_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "es:ListDomainNames",
                "required",
                "OpenSearch cost review requires es:ListDomainNames to collect read-only OpenSearch domain, OpenSearch node, EBS volume evidence.",
                chargeable=False,
                evidence_categories=OPENSEARCH_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="es:ListDomainNames is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "es:DescribeDomains",
                "required",
                "OpenSearch cost review requires es:DescribeDomains to collect read-only OpenSearch domain, OpenSearch node, EBS volume evidence.",
                chargeable=False,
                evidence_categories=OPENSEARCH_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="es:DescribeDomains is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "OpenSearch cost review requires ce:GetCostAndUsage to collect read-only OpenSearch domain, OpenSearch node, EBS volume evidence.",
                chargeable=False,
                evidence_categories=OPENSEARCH_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "redshift-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Redshift cost review requires ec2:DescribeRegions to collect read-only Redshift cluster, Redshift "
                "Serverless namespace, Redshift Serverless workgroup evidence.",
                chargeable=False,
                evidence_categories=REDSHIFT_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "redshift:DescribeClusters",
                "required",
                "Redshift cost review requires redshift:DescribeClusters to collect read-only Redshift cluster, "
                "Redshift Serverless namespace, Redshift Serverless workgroup evidence.",
                chargeable=False,
                evidence_categories=REDSHIFT_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="redshift:DescribeClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "redshift-serverless:ListNamespaces",
                "required",
                "Redshift cost review requires redshift-serverless:ListNamespaces to collect read-only "
                "Redshift cluster, Redshift Serverless namespace, Redshift Serverless workgroup evidence.",
                chargeable=False,
                evidence_categories=REDSHIFT_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="redshift-serverless:ListNamespaces is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "redshift-serverless:ListWorkgroups",
                "required",
                "Redshift cost review requires redshift-serverless:ListWorkgroups to collect read-only "
                "Redshift cluster, Redshift Serverless namespace, Redshift Serverless workgroup evidence.",
                chargeable=False,
                evidence_categories=REDSHIFT_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="redshift-serverless:ListWorkgroups is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Redshift cost review requires ce:GetCostAndUsage to collect read-only Redshift cluster, Redshift "
                "Serverless namespace, Redshift Serverless workgroup evidence.",
                chargeable=False,
                evidence_categories=REDSHIFT_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
