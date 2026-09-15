from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE = (
    "VPC Flow Log",
    "Network flow",
)

VPC_FLOW_LOG_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "vpc-flow-log-attribution": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "VPC Flow Log attribution requires ec2:DescribeRegions to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=False,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeFlowLogs",
                "required",
                "VPC Flow Log attribution requires ec2:DescribeFlowLogs to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=False,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeFlowLogs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNetworkInterfaces",
                "required",
                "VPC Flow Log attribution requires ec2:DescribeNetworkInterfaces to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=False,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNetworkInterfaces is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeRouteTables",
                "required",
                "VPC Flow Log attribution requires ec2:DescribeRouteTables to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=False,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRouteTables is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "logs:StartQuery",
                "required",
                "VPC Flow Log attribution requires logs:StartQuery to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=True,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="logs:StartQuery is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "logs:GetQueryResults",
                "required",
                "VPC Flow Log attribution requires logs:GetQueryResults to collect read-only VPC Flow Log, Network flow evidence.",
                chargeable=True,
                evidence_categories=VPC_FLOW_LOG_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="logs:GetQueryResults is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
