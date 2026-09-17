from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

PLATFORM_SCANNERS: dict[str, ScannerDefinition] = {
    "api-gateway-cost-review": ScannerDefinition(
        scanner_id="api-gateway-cost-review",
        display_name="API Gateway cost review",
        description=(
            "Reviews API Gateway REST, HTTP, and WebSocket API endpoint type, "
            "route, authorization, auto-deploy, cache, VPC link, request "
            "guardrail, logging, detailed metrics, data trace, and X-Ray "
            "settings as cost-governance signals."
        ),
        aws_services=("Amazon API Gateway", "Amazon CloudWatch", "AWS X-Ray"),
        resource_types=("API Gateway API", "API Gateway stage"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "apigateway:GET",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "apigateway:GetRestApis",
            "apigateway:GetStages",
            "apigateway:GetVpcLinks",
            "apigatewayv2:GetApis",
            "apigatewayv2:GetStages",
            "apigatewayv2:GetRoutes",
            "apigatewayv2:GetVpcLinks",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=(
            "api_gateway_cache_cost_review",
            "api_gateway_observability_cost_review",
            "api_gateway_vpc_link_cost_review",
            "api_gateway_request_guardrail_review",
        ),
        maturity="experimental",
        limitations=(
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual APIs or stages.",
            "Does not calculate exact API Gateway request, cache, log, metric, or X-Ray cost without billing evidence.",
            "Does not recommend disabling observability or cache settings without workload validation.",
            "Does not infer idle APIs without request metrics or billing evidence.",
            "Request guardrail findings do not prove missing protection if usage plans, WAF, or upstream throttling exist outside visible stage metadata.",
            "vpc_link_detail_mode can be set to summary for faster development scans, but VPC link findings require full mode.",
        ),
        cloudwatch_namespaces_used=("AWS/ApiGateway",),
        metrics_used=(
            "Count",
            "Latency",
            "4XXError",
            "5XXError",
            "CacheHitCount",
            "CacheMissCount",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects API Gateway stage, route, VPC link, observability, request "
            "guardrail, and cost-context records during collection and analyzes "
            "only serialized API Gateway evidence without AWS clients."
        ),
    ),
    "eks-cost-risk-review": ScannerDefinition(
        scanner_id="eks-cost-risk-review",
        display_name="EKS cost risk review",
        description=(
            "Reviews EKS cluster, node group, Fargate profile, endpoint, and "
            "version metadata as managed-platform cost and lifecycle signals, "
            "including clusters with no visible managed compute attachment."
        ),
        aws_services=("Amazon EKS", "Amazon EC2", "Amazon CloudWatch"),
        resource_types=("EKS cluster", "EKS managed node group", "Fargate profile"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "eks:ListClusters",
            "eks:DescribeCluster",
            "eks:ListNodegroups",
            "eks:DescribeNodegroup",
            "eks:ListFargateProfiles",
            "eks:DescribeFargateProfile",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "eks:ListClusters",
            "eks:DescribeCluster",
            "eks:ListNodegroups",
            "eks:DescribeNodegroup",
            "eks:ListFargateProfiles",
            "eks:DescribeFargateProfile",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("eks_cluster_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not collect Kubernetes workload inventory or pod utilization.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual clusters.",
            "Does not calculate exact cluster, node, load balancer, NAT, EBS, or log cost without billing evidence.",
            "Does not recommend deleting or resizing clusters, node groups, or workloads.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects EKS cluster, node group, Fargate profile, and cost-context "
            "records during collection and analyzes only serialized EKS evidence "
            "without AWS clients."
        ),
    ),
    "ecs-cost-governance-review": ScannerDefinition(
        scanner_id="ecs-cost-governance-review",
        display_name="ECS cost governance review",
        description=(
            "Reviews ECS cluster, service, launch type, desired/running task, "
            "capacity-provider, task-definition, deployment, event, and tag "
            "metadata as managed-platform cost governance signals."
        ),
        aws_services=("Amazon ECS", "AWS Fargate", "AWS Cost Explorer"),
        resource_types=("ECS cluster", "ECS service"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ecs:ListClusters",
            "ecs:DescribeClusters",
            "ecs:ListServices",
            "ecs:DescribeServices",
            "ecs:DescribeTaskDefinition",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ecs:ListClusters",
            "ecs:DescribeClusters",
            "ecs:ListServices",
            "ecs:DescribeServices",
            "ecs:DescribeTaskDefinition",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("ecs_cost_governance_review",),
        maturity="experimental",
        limitations=(
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual ECS services.",
            "Does not inspect container-level utilization, logs, task networking, or application traffic.",
            "Does not calculate supporting EC2, ALB, NAT, EBS, or log cost without billing export evidence.",
            "Does not stop, scale, delete, or change ECS services or clusters.",
            (
                "task_definition_detail_mode can be set to summary for faster "
                "development scans, but task definition CPU and memory sizing "
                "facts require full mode."
            ),
            (
                "regional_collection_mode can be set to billing-active for faster "
                "development scans, but final reviews should use full regional "
                "collection because EC2-backed ECS cost can appear outside ECS or "
                "Fargate service lines."
            ),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects ECS cluster, service, task definition, regional billing, "
            "and cost-context records during collection and analyzes only "
            "serialized ECS evidence without AWS clients."
        ),
    ),
    "redshift-cost-review": ScannerDefinition(
        scanner_id="redshift-cost-review",
        display_name="Redshift cost review",
        description=(
            "Reviews Redshift cluster and serverless metadata as analytics warehouse cost-governance signals, including visible serverless capacity settings."
        ),
        aws_services=(
            "Amazon Redshift",
            "Amazon Redshift Serverless",
            "Amazon CloudWatch",
        ),
        resource_types=(
            "Redshift cluster",
            "Redshift Serverless namespace",
            "Redshift Serverless workgroup",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "redshift:DescribeClusters",
            "redshift-serverless:ListNamespaces",
            "redshift-serverless:ListWorkgroups",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "redshift:DescribeClusters",
            "redshift-serverless:ListNamespaces",
            "redshift-serverless:ListWorkgroups",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("redshift_cluster_cost_review",),
        maturity="experimental",
        limitations=(
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual warehouses.",
            "Does not collect query volume, CPU, storage utilization, or per-cluster billing attribution.",
            "Does not prove a warehouse is idle or oversized without workload and metric evidence.",
            "Does not recommend pausing, resizing, deleting, or changing Redshift resources without validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Redshift cluster, serverless, and cost-context records "
            "during collection and analyzes only serialized Redshift evidence "
            "without AWS clients."
        ),
    ),
    "elasticache-cost-review": ScannerDefinition(
        scanner_id="elasticache-cost-review",
        display_name="ElastiCache cost review",
        description=(
            "Reviews ElastiCache cluster, replication group, node count, "
            "multi-AZ, failover, cluster-mode metadata, and available "
            "CloudWatch utilization signals as managed-platform cost signals."
        ),
        aws_services=("Amazon ElastiCache", "Amazon CloudWatch"),
        resource_types=(
            "ElastiCache cache cluster",
            "ElastiCache replication group",
            "Cache node",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "elasticache:DescribeCacheClusters",
            "elasticache:DescribeReplicationGroups",
            "cloudwatch:GetMetricData",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "elasticache:DescribeCacheClusters",
            "elasticache:DescribeReplicationGroups",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("elasticache_cluster_cost_review",),
        cloudwatch_namespaces_used=("AWS/ElastiCache",),
        metrics_used=(
            "CPUUtilization",
            "EngineCPUUtilization",
            "DatabaseMemoryUsagePercentage",
            "CurrConnections",
            "Evictions",
            "CacheHits",
            "CacheMisses",
        ),
        maturity="experimental",
        limitations=(
            "Collects best-effort CloudWatch metric context where datapoints are available.",
            "metric_detail_mode can be set to summary for faster development scans that defer CloudWatch metric enrichment.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual cache clusters.",
            "Does not calculate cache hit ratio or exact per-cluster billing attribution.",
            "Does not prove a cache cluster is idle or oversized without workload-owner validation.",
            "Does not recommend resizing, deleting, or changing ElastiCache resources without validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects ElastiCache cluster, replication group, metric, and "
            "cost-context records during collection and analyzes only serialized "
            "ElastiCache evidence without AWS clients."
        ),
    ),
    "opensearch-cost-review": ScannerDefinition(
        scanner_id="opensearch-cost-review",
        display_name="OpenSearch cost review",
        description=(
            "Reviews OpenSearch domain capacity, storage, multi-AZ, dedicated master, warm storage, and processing metadata as managed-platform cost signals."
        ),
        aws_services=("Amazon OpenSearch Service", "Amazon CloudWatch"),
        resource_types=("OpenSearch domain", "OpenSearch node", "EBS volume"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "es:ListDomainNames",
            "es:DescribeDomains",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "opensearch:ListDomainNames",
            "opensearch:DescribeDomains",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("opensearch_domain_cost_review",),
        maturity="experimental",
        limitations=(
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual domains.",
            "Does not collect per-domain billing, shard count, index lifecycle policy, or utilization metrics.",
            "Does not prove that a domain is oversized or idle without workload and metric evidence.",
            "Does not recommend resizing, deleting, or changing OpenSearch domains without validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects OpenSearch domain, capacity, storage, and cost-context "
            "records during collection and analyzes only serialized OpenSearch "
            "evidence without AWS clients."
        ),
    ),
}

PLATFORM_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "platform",
    PLATFORM_SCANNERS,
)
