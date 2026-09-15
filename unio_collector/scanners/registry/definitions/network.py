from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

NETWORK_SCANNERS: dict[str, ScannerDefinition] = {
    "cloudfront-alb-origin-protection-review": ScannerDefinition(
        scanner_id="cloudfront-alb-origin-protection-review",
        display_name="CloudFront ALB origin protection review",
        description=(
            "Reviews CloudFront distributions with Application Load Balancer "
            "origins using explicit CloudFront origin, ALB, listener, "
            "security-group, WAF, and origin-verification evidence."
        ),
        aws_services=(
            "Amazon CloudFront",
            "Elastic Load Balancing",
            "Amazon EC2",
            "AWS WAF",
        ),
        resource_types=(
            "CloudFront distribution",
            "CloudFront origin",
            "Application Load Balancer",
            "ALB listener",
            "EC2 security group",
            "WAF web ACL association",
            "ALB listener rule",
            "CloudFront VPC origin",
            "CloudFront managed prefix list",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "cloudfront:ListDistributions",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeListeners",
            "ec2:DescribeSecurityGroups",
            "wafv2:GetWebACLForResource",
            "elasticloadbalancing:DescribeRules",
            "ec2:DescribeManagedPrefixLists",
        ),
        conditional_iam_actions=(
            "cloudfront:GetOriginRequestPolicy",
            "cloudfront:GetVpcOrigin",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "cloudfront:ListDistributions",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeListeners",
            "elbv2:DescribeLoadBalancers",
            "elbv2:DescribeListeners",
            "ec2:DescribeSecurityGroups",
            "wafv2:GetWebACLForResource",
            "elasticloadbalancing:DescribeRules",
            "elbv2:DescribeRules",
            "cloudfront:GetOriginRequestPolicy",
            "cloudfront:GetVpcOrigin",
            "ec2:DescribeManagedPrefixLists",
        ),
        risk_level="medium",
        output_finding_types=("cloudfront_alb_origin_protection_review",),
        maturity="experimental",
        limitations=(
            "Uses explicit CloudFront origin and ALB DNS/name/ARN evidence only.",
            "Does not infer DNS, simulate network paths, probe origins, or prove exploitability.",
            "Does not claim WAF bypass unless direct ALB exposure and WAF association scope support that review question.",
            "Missing CloudFront-to-ALB, listener, security-group, or WAF evidence is treated as incomplete evidence.",
            "Does not recommend or execute automatic CloudFront, WAF, ALB, listener, or security-group changes.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized CloudFront ALB origin protection evidence and does not create AWS clients during replay."),
    ),
    "cloudfront-origin-cost-review": ScannerDefinition(
        scanner_id="cloudfront-origin-cost-review",
        display_name="CloudFront origin cost review",
        description=(
            "Reviews CloudFront distribution state, origin classification, cache "
            "behavior, price class, forwarding, compression, logging destination, "
            "recent invalidation, ownership metadata, and optional standard "
            "request/byte/error metrics for edge-delivery cost governance."
        ),
        aws_services=("Amazon CloudFront", "Amazon CloudWatch"),
        resource_types=(
            "CloudFront distribution",
            "CloudFront origin",
            "Cache behavior",
            "CloudFront invalidation",
        ),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=(
            "cloudfront:ListDistributions",
            "cloudfront:ListTagsForResource",
            "cloudfront:ListInvalidations",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "cloudfront:ListDistributions",
            "cloudfront:ListTagsForResource",
            "cloudfront:ListInvalidations",
            "cloudwatch:GetMetricData",
        ),
        risk_level="medium",
        output_finding_types=("cloudfront_origin_cost_review",),
        cloudwatch_namespaces_used=("AWS/CloudFront",),
        metrics_used=(
            "Requests",
            "BytesDownloaded",
            "BytesUploaded",
            "4xxErrorRate",
            "5xxErrorRate",
        ),
        conditional_iam_actions=("cloudwatch:GetMetricData",),
        maturity="experimental",
        limitations=(
            ("CloudWatch GetMetricData enrichment is skipped unless chargeable scanners are explicitly allowed."),
            (
                "Uses distribution-level CloudFront standard metrics when "
                "allowed and available, but does not collect cache hit ratio, "
                "origin bytes, or exact per-distribution billing."
            ),
            ("invalidation_detail_mode can be set to summary for faster development scans that defer ListInvalidations evidence."),
            ("Does not prove that any distribution, origin, or cache policy is wasteful."),
            ("Does not recommend disabling distributions or changing cache behaviour without validation."),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzes serialized CloudFront distribution records without AWS "
            "clients; metric and invalidation collection limitations remain "
            "collector-side evidence."
        ),
    ),
    "network-public-ipv4-review": ScannerDefinition(
        scanner_id="network-public-ipv4-review",
        display_name="Public IPv4 cost review",
        description=("Reviews regional public IPv4 address footprint using EC2 address and network interface metadata."),
        aws_services=("Amazon VPC", "Amazon EC2"),
        resource_types=("Public IPv4 address", "Elastic IP", "Network interface"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeAddresses",
            "ec2:DescribeNetworkInterfaces",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeAddresses",
            "ec2:DescribeNetworkInterfaces",
        ),
        risk_level="medium",
        output_finding_types=("network_public_ipv4_footprint",),
        maturity="experimental",
        limitations=(
            "Does not prove that an attached public IPv4 address is unnecessary.",
            "Does not inspect external DNS, allow-lists, firewall rules, or client dependencies.",
            "Cost impact depends on the AWS public IPv4 pricing period and account usage.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Collects EC2 public IPv4 footprint records and analyzes only those serialized evidence records without AWS clients."),
    ),
    "network-vpc-endpoint-opportunity-review": ScannerDefinition(
        scanner_id="network-vpc-endpoint-opportunity-review",
        display_name="VPC endpoint opportunity review",
        description=(
            "Reviews NAT-routed VPC route tables against S3 and DynamoDB gateway endpoint presence and route-table coverage using EC2 networking metadata."
        ),
        aws_services=("Amazon VPC", "Amazon EC2"),
        resource_types=("VPC", "Route table", "NAT Gateway", "VPC endpoint"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeVpcs",
            "ec2:DescribeRouteTables",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeNatGateways",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeSubnets",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeVpcs",
            "ec2:DescribeRouteTables",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeNatGateways",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeSubnets",
        ),
        risk_level="medium",
        output_finding_types=("network_vpc_endpoint_opportunity",),
        maturity="experimental",
        limitations=(
            "Does not query VPC Flow Logs or prove exact traffic paths.",
            ("Flags missing or partial S3/DynamoDB gateway endpoint route-table coverage, but does not prove those services are used by workloads."),
            "Does not inspect workload service usage, DNS behaviour, or endpoint policy fit.",
            (
                "Subnet and network-interface context uses explicit route-table "
                "associations plus main route-table subnet inference where subnet "
                "metadata is available."
            ),
            "Does not recommend route, endpoint, or NAT Gateway changes without validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects bounded neutral VPC topology with cached completeness; offline analysis "
            "derives endpoint candidates while retaining legacy opportunity-record replay."
        ),
    ),
    "network-privatelink-cost-review": ScannerDefinition(
        scanner_id="network-privatelink-cost-review",
        display_name="PrivateLink cost review",
        description=("Reviews interface endpoints, Gateway Load Balancer endpoints, and owned endpoint services using EC2 VPC endpoint metadata."),
        aws_services=("Amazon VPC", "Amazon EC2"),
        resource_types=(
            "VPC endpoint",
            "Interface endpoint",
            "Gateway Load Balancer endpoint",
            "VPC endpoint service",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeVpcEndpointServiceConfigurations",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeVpcEndpointServiceConfigurations",
        ),
        risk_level="medium",
        output_finding_types=("network_privatelink_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not collect endpoint byte volume or exact PrivateLink billing.",
            "Does not prove that an endpoint or endpoint service is unnecessary.",
            "Does not inspect DNS, endpoint policies, security groups, or consumers.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects VPC endpoint and endpoint-service regional records and analyzes only serialized PrivateLink evidence without AWS clients."
        ),
    ),
    "network-transit-gateway-cost-review": ScannerDefinition(
        scanner_id="network-transit-gateway-cost-review",
        display_name="Transit Gateway cost review",
        description=("Reviews Transit Gateway, attachment, and route table footprint using EC2 networking metadata."),
        aws_services=("Amazon VPC", "Amazon EC2"),
        resource_types=(
            "Transit Gateway",
            "Transit Gateway attachment",
            "Transit Gateway route table",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeTransitGateways",
            "ec2:DescribeTransitGatewayAttachments",
            "ec2:DescribeTransitGatewayRouteTables",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeTransitGateways",
            "ec2:DescribeTransitGatewayAttachments",
            "ec2:DescribeTransitGatewayRouteTables",
        ),
        risk_level="medium",
        output_finding_types=("network_transit_gateway_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not prove data-processing volume or exact traffic paths.",
            ("Does not provide per-attachment billing attribution without Cost Explorer, CUR/Data Export, or flow evidence."),
            "Does not recommend detaching or deleting network connectivity.",
            "Cost opportunity needs Cost Explorer, CUR, or flow evidence validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Collects Transit Gateway regional records and analyzes only those serialized evidence records without AWS clients."),
    ),
    "nat-gateway-cost-review": ScannerDefinition(
        scanner_id="nat-gateway-cost-review",
        display_name="NAT Gateway cost review",
        description="Combines NAT Gateway inventory with billing usage signals where available.",
        aws_services=("Amazon VPC", "AWS Cost Explorer"),
        resource_types=("NAT Gateway", "Cost Explorer usage type"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeNatGateways",
            "cloudwatch:GetMetricData",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeNatGateways",
            "cloudwatch:GetMetricData",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("nat_gateway_context", "nat_gateway_cost_review"),
        maturity="experimental",
        limitations=(
            (
                "Does not treat NAT inventory or billing alone as a replacement recommendation; the automation layer requires "
                "separate complete route, flow, environment, and endpoint evidence."
            ),
            "No route, endpoint, security-group, or NAT resource is changed.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzes serialized NAT inventory and Cost Explorer usage evidence without AWS clients."),
    ),
    "data-transfer-cost-review": ScannerDefinition(
        scanner_id="data-transfer-cost-review",
        display_name="Data transfer cost review",
        description="Checks Cost Explorer usage types for egress, NAT, cross-region, and cross-AZ cost signals.",
        aws_services=("AWS Cost Explorer",),
        resource_types=("Cost Explorer usage type",),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=("ce:GetCostAndUsage",),
        required_permission_level="read_only",
        aws_api_calls=("ce:GetCostAndUsage",),
        risk_level="medium",
        output_finding_types=("data_transfer_cost_review",),
        maturity="experimental",
        limitations=("Billing usage types are cost signals, not network path proof.",),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Cost Explorer usage-type records during collection and analyzes only serialized daily cost evidence without AWS clients."
        ),
    ),
    "cur-data-export-attribution": ScannerDefinition(
        scanner_id="cur-data-export-attribution",
        display_name="CUR/Data Export attribution",
        description=("Reads CUR/Data Export CSV files to add resource-level and tag-level billing evidence where available."),
        aws_services=("AWS Billing", "AWS Cost and Usage Report", "AWS Data Exports"),
        resource_types=("CUR line item", "Billing resource", "Cost allocation tag"),
        default_enabled=False,
        supports_regions=True,
        required_iam_actions=("s3:GetObject",),
        required_permission_level="read_only",
        aws_api_calls=("s3:GetObject",),
        risk_level="low",
        output_finding_types=(
            "cur_data_export_resource_cost_signal",
            "cur_data_export_unassigned_cost",
        ),
        maturity="experimental",
        limitations=(
            ("CSV, CSV.GZ, directory, and manifest JSON inputs are supported."),
            "S3 object reads require s3:GetObject and an explicitly supplied S3 URI.",
            "Does not query Athena or read Parquet in this phase.",
            "High resource cost is not cleanup evidence without ownership and utilization context.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Consumes serialized CUR/Data Export summaries and prebuilt findings without AWS clients; source access remains a collection concern."
        ),
    ),
    "vpc-flow-log-attribution": ScannerDefinition(
        scanner_id="vpc-flow-log-attribution",
        display_name="VPC Flow Log attribution",
        description=("Uses CloudWatch Logs Insights over VPC Flow Logs to identify high-volume source/destination pairs for data-transfer investigation."),
        aws_services=("Amazon VPC", "Amazon CloudWatch Logs"),
        resource_types=("VPC Flow Log", "Network flow"),
        default_enabled=False,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeFlowLogs",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeRouteTables",
            "logs:StartQuery",
            "logs:GetQueryResults",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeFlowLogs",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeRouteTables",
            "logs:StartQuery",
            "logs:GetQueryResults",
        ),
        risk_level="medium",
        output_finding_types=(
            "vpc_flow_log_attribution",
            "vpc_flow_log_attribution_unavailable",
        ),
        maturity="experimental",
        limitations=(
            "Only CloudWatch Logs-backed VPC Flow Logs are queried.",
            "Logs Insights queries are read-only but can incur CloudWatch Logs query charges.",
            "Attempts ENI/subnet/AZ enrichment for private IPs where permissions allow.",
            "Attempts route table default route enrichment where permissions allow.",
            "Does not prove NAT Gateway billing path selection.",
            "Flow logs provide network path evidence, not direct billing proof.",
        ),
        execution_phase="dependent",
        may_incur_charges=True,
        chargeable_reason=(
            "Uses CloudWatch Logs Insights StartQuery/GetQueryResults over VPC Flow Logs. AWS may charge for the log data scanned by those queries."
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Carries flow-log attribution records, query metadata, selected "
            "regions, and query-window metadata in serialized evidence; "
            "billing correlation side effects are optional during offline "
            "analysis."
        ),
    ),
}

NETWORK_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "network",
    NETWORK_SCANNERS,
)
