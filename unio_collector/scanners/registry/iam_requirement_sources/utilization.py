from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

BACKUP_RETENTION_REVIEW_EVIDENCE = (
    "Backup recovery point",
    "Backup plan",
    "Backup vault",
)

EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE = (
    "RDS instance",
    "Lambda function",
    "EC2 instance AMI",
    "ElastiCache cluster",
    "OpenSearch domain",
    "EKS cluster",
)

LOAD_BALANCER_IDLE_REVIEW_EVIDENCE = (
    "Application Load Balancer",
    "Network Load Balancer",
)

RDS_SNAPSHOT_RETENTION_REVIEW_EVIDENCE = (
    "RDS DB snapshot",
    "RDS DB cluster snapshot",
)

RDS_UTILIZATION_REVIEW_EVIDENCE = ("RDS DB instance",)

SNAPSHOT_AGE_REVIEW_EVIDENCE = ("EBS snapshot",)

UTILIZATION_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "backup-retention-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "backup:ListBackupVaults",
                "required",
                "Backup retention review requires backup:ListBackupVaults to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:ListBackupVaults is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:ListRecoveryPointsByBackupVault",
                "required",
                "Backup retention review requires backup:ListRecoveryPointsByBackupVault to collect "
                "read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:ListRecoveryPointsByBackupVault is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:ListBackupPlans",
                "required",
                "Backup retention review requires backup:ListBackupPlans to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:ListBackupPlans is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:GetBackupPlan",
                "required",
                "Backup retention review requires backup:GetBackupPlan to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:GetBackupPlan is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:ListBackupSelections",
                "required",
                "Backup retention review requires backup:ListBackupSelections to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:ListBackupSelections is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:GetBackupSelection",
                "required",
                "Backup retention review requires backup:GetBackupSelection to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:GetBackupSelection is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "backup:ListTags",
                "required",
                "Backup retention review requires backup:ListTags to collect read-only Backup recovery point, Backup plan, Backup vault evidence.",
                chargeable=False,
                evidence_categories=BACKUP_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="backup:ListTags is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "extended-support-and-eol-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "rds:DescribeDBInstances",
                "required",
                "Extended support and EOL review requires rds:DescribeDBInstances to collect read-only RDS instance, "
                "Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:DescribeDBInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "rds:ListTagsForResource",
                "required",
                "Extended support and EOL review requires rds:ListTagsForResource to collect read-only RDS instance, "
                "Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lambda:ListFunctions",
                "required",
                "Extended support and EOL review requires lambda:ListFunctions to collect read-only RDS instance, Lambda "
                "function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:ListFunctions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeInstances",
                "required",
                "Extended support and EOL review requires ec2:DescribeInstances to collect read-only RDS instance, "
                "Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeImages",
                "required",
                "Extended support and EOL review requires ec2:DescribeImages to collect read-only RDS instance, Lambda "
                "function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeImages is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticache:DescribeCacheClusters",
                "required",
                "Extended support and EOL review requires elasticache:DescribeCacheClusters to collect "
                "read-only RDS instance, Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch "
                "domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticache:DescribeCacheClusters is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "opensearch:ListDomainNames",
                "required",
                "Extended support and EOL review requires opensearch:ListDomainNames to collect read-only RDS "
                "instance, Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster "
                "evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="opensearch:ListDomainNames is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "opensearch:DescribeDomains",
                "required",
                "Extended support and EOL review requires opensearch:DescribeDomains to collect read-only RDS "
                "instance, Lambda function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster "
                "evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="opensearch:DescribeDomains is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:ListClusters",
                "required",
                "Extended support and EOL review requires eks:ListClusters to collect read-only RDS instance, Lambda "
                "function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:ListClusters is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "eks:DescribeCluster",
                "required",
                "Extended support and EOL review requires eks:DescribeCluster to collect read-only RDS instance, Lambda "
                "function, EC2 instance AMI, ElastiCache cluster, OpenSearch domain, EKS cluster evidence.",
                chargeable=False,
                evidence_categories=EXTENDED_SUPPORT_AND_EOL_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="eks:DescribeCluster is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "load-balancer-idle-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "elasticloadbalancing:DescribeLoadBalancers",
                "required",
                "Load balancer idle review requires elasticloadbalancing:DescribeLoadBalancers to "
                "collect read-only Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTargetGroups",
                "required",
                "Load balancer idle review requires elasticloadbalancing:DescribeTargetGroups to "
                "collect read-only Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTargetGroups is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTargetHealth",
                "required",
                "Load balancer idle review requires elasticloadbalancing:DescribeTargetHealth to "
                "collect read-only Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTargetHealth is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTags",
                "required",
                "Load balancer idle review requires elasticloadbalancing:DescribeTags to collect read-only "
                "Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTags is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "Load balancer idle review requires cloudwatch:GetMetricData to collect read-only Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "Load balancer idle review requires cloudwatch:GetMetricStatistics to collect read-only "
                "Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=LOAD_BALANCER_IDLE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "rds-snapshot-retention-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "rds:DescribeDBSnapshots",
                "required",
                "RDS snapshot retention review requires rds:DescribeDBSnapshots to collect read-only RDS DB snapshot, RDS DB cluster snapshot evidence.",
                chargeable=False,
                evidence_categories=RDS_SNAPSHOT_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:DescribeDBSnapshots is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "rds:DescribeDBClusterSnapshots",
                "required",
                "RDS snapshot retention review requires rds:DescribeDBClusterSnapshots to collect read-only RDS DB snapshot, RDS DB cluster snapshot evidence.",
                chargeable=False,
                evidence_categories=RDS_SNAPSHOT_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:DescribeDBClusterSnapshots is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "rds:ListTagsForResource",
                "required",
                "RDS snapshot retention review requires rds:ListTagsForResource to collect read-only RDS DB snapshot, RDS DB cluster snapshot evidence.",
                chargeable=False,
                evidence_categories=RDS_SNAPSHOT_RETENTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "rds-utilization-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "rds:DescribeDBInstances",
                "required",
                "RDS utilization review requires rds:DescribeDBInstances to collect read-only RDS DB instance evidence.",
                chargeable=False,
                evidence_categories=RDS_UTILIZATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:DescribeDBInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "rds:ListTagsForResource",
                "required",
                "RDS utilization review requires rds:ListTagsForResource to collect read-only RDS DB instance evidence.",
                chargeable=False,
                evidence_categories=RDS_UTILIZATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="rds:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "RDS utilization review requires cloudwatch:GetMetricData to collect read-only RDS DB instance evidence.",
                chargeable=False,
                evidence_categories=RDS_UTILIZATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "RDS utilization review requires cloudwatch:GetMetricStatistics to collect read-only RDS DB instance evidence.",
                chargeable=False,
                evidence_categories=RDS_UTILIZATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "snapshot-age-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Snapshot age review requires ec2:DescribeRegions to collect read-only EBS snapshot evidence.",
                chargeable=False,
                evidence_categories=SNAPSHOT_AGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSnapshots",
                "required",
                "Snapshot age review requires ec2:DescribeSnapshots to collect read-only EBS snapshot evidence.",
                chargeable=False,
                evidence_categories=SNAPSHOT_AGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSnapshots is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
