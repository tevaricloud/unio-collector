from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

EC2_IDLE_INSTANCE_REVIEW_EVIDENCE = ("EC2 instance",)

EC2_STOPPED_INSTANCES_WITH_STORAGE_EVIDENCE = (
    "EC2 instance",
    "EBS volume",
)

EC2_UNASSOCIATED_ELASTIC_IPS_EVIDENCE = ("Elastic IP",)

EC2_UNATTACHED_EBS_VOLUMES_EVIDENCE = ("EBS volume",)

IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE = (
    "Elastic IP",
    "EBS volume",
    "EC2 instance",
    "NAT Gateway",
)

NAT_GATEWAY_INVENTORY_EVIDENCE = ("NAT Gateway",)

PROVISIONED_IOPS_REVIEW_EVIDENCE = ("EBS volume",)

EC2_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "ec2-idle-instance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "EC2 idle instance review requires ec2:DescribeRegions to collect read-only EC2 instance evidence.",
                chargeable=False,
                evidence_categories=EC2_IDLE_INSTANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeInstances",
                "required",
                "EC2 idle instance review requires ec2:DescribeInstances to collect read-only EC2 instance evidence.",
                chargeable=False,
                evidence_categories=EC2_IDLE_INSTANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "EC2 idle instance review requires cloudwatch:GetMetricData to collect read-only EC2 instance evidence.",
                chargeable=False,
                evidence_categories=EC2_IDLE_INSTANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "EC2 idle instance review requires cloudwatch:GetMetricStatistics to collect read-only EC2 instance evidence.",
                chargeable=False,
                evidence_categories=EC2_IDLE_INSTANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "ec2-stopped-instances-with-storage": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Stopped EC2 instances with storage requires ec2:DescribeRegions to collect read-only EC2 instance, EBS volume evidence.",
                chargeable=False,
                evidence_categories=EC2_STOPPED_INSTANCES_WITH_STORAGE_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeInstances",
                "required",
                "Stopped EC2 instances with storage requires ec2:DescribeInstances to collect read-only EC2 instance, EBS volume evidence.",
                chargeable=False,
                evidence_categories=EC2_STOPPED_INSTANCES_WITH_STORAGE_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "ec2-unassociated-elastic-ips": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Unassociated Elastic IPs requires ec2:DescribeRegions to collect read-only Elastic IP evidence.",
                chargeable=False,
                evidence_categories=EC2_UNASSOCIATED_ELASTIC_IPS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeAddresses",
                "required",
                "Unassociated Elastic IPs requires ec2:DescribeAddresses to collect read-only Elastic IP evidence.",
                chargeable=False,
                evidence_categories=EC2_UNASSOCIATED_ELASTIC_IPS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeAddresses is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "ec2-unattached-ebs-volumes": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Unattached EBS volumes requires ec2:DescribeRegions to collect read-only EBS volume evidence.",
                chargeable=False,
                evidence_categories=EC2_UNATTACHED_EBS_VOLUMES_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVolumes",
                "required",
                "Unattached EBS volumes requires ec2:DescribeVolumes to collect read-only EBS volume evidence.",
                chargeable=False,
                evidence_categories=EC2_UNATTACHED_EBS_VOLUMES_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVolumes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "idle-zombie-resource-detector": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Idle/zombie resource detector requires ec2:DescribeRegions to collect read-only Elastic IP, EBS volume, EC2 instance, NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeAddresses",
                "required",
                "Idle/zombie resource detector requires ec2:DescribeAddresses to collect read-only Elastic IP, EBS volume, EC2 instance, NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeAddresses is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVolumes",
                "required",
                "Idle/zombie resource detector requires ec2:DescribeVolumes to collect read-only Elastic IP, EBS volume, EC2 instance, NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVolumes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeInstances",
                "required",
                "Idle/zombie resource detector requires ec2:DescribeInstances to collect read-only Elastic IP, EBS volume, EC2 instance, NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "Idle/zombie resource detector requires ec2:DescribeNatGateways to collect read-only Elastic IP, EBS "
                "volume, EC2 instance, NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=IDLE_ZOMBIE_RESOURCE_DETECTOR_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "nat-gateway-inventory": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "NAT Gateway inventory context requires ec2:DescribeRegions to collect read-only NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_INVENTORY_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "NAT Gateway inventory context requires ec2:DescribeNatGateways to collect read-only NAT Gateway evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_INVENTORY_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "provisioned-iops-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Provisioned IOPS review requires ec2:DescribeRegions to collect read-only EBS volume evidence.",
                chargeable=False,
                evidence_categories=PROVISIONED_IOPS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVolumes",
                "required",
                "Provisioned IOPS review requires ec2:DescribeVolumes to collect read-only EBS volume evidence.",
                chargeable=False,
                evidence_categories=PROVISIONED_IOPS_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVolumes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
