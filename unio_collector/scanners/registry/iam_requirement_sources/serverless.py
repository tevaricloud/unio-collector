from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE = (
    "Lambda function",
    "S3 bucket notification",
    "CloudWatch log group",
)

SQS_LAMBDA_POLLING_COST_REVIEW_EVIDENCE = ("Lambda event source mapping",)

SERVERLESS_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "lambda-cost-cycle-risk-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "lambda:ListFunctions",
                "required",
                "Lambda cost and cycle-risk review requires lambda:ListFunctions to collect read-only Lambda function, "
                "S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:ListFunctions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lambda:GetFunctionConfiguration",
                "required",
                "Lambda cost and cycle-risk review requires lambda:GetFunctionConfiguration to collect "
                "read-only Lambda function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:GetFunctionConfiguration is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lambda:ListTags",
                "required",
                "Lambda cost and cycle-risk review requires lambda:ListTags to collect read-only Lambda function, S3 bucket "
                "notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:ListTags is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lambda:GetFunctionEventInvokeConfig",
                "required",
                "Lambda cost and cycle-risk review requires lambda:GetFunctionEventInvokeConfig to "
                "collect read-only Lambda function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:GetFunctionEventInvokeConfig is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lambda:ListEventSourceMappings",
                "required",
                "Lambda cost and cycle-risk review requires lambda:ListEventSourceMappings to collect "
                "read-only Lambda function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:ListEventSourceMappings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:ListAllMyBuckets",
                "required",
                "Lambda cost and cycle-risk review requires s3:ListAllMyBuckets to collect read-only Lambda function, S3 "
                "bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:ListAllMyBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "s3:GetBucketNotification",
                "required",
                "Lambda cost and cycle-risk review requires s3:GetBucketNotification to collect read-only Lambda "
                "function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetBucketNotification is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "Lambda cost and cycle-risk review requires cloudwatch:GetMetricData to collect read-only Lambda "
                "function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "Lambda cost and cycle-risk review requires cloudwatch:GetMetricStatistics to collect "
                "read-only Lambda function, S3 bucket notification, CloudWatch log group evidence.",
                chargeable=False,
                evidence_categories=LAMBDA_COST_CYCLE_RISK_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "sqs-lambda-polling-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "lambda:ListEventSourceMappings",
                "required",
                "SQS Lambda polling cost review requires lambda:ListEventSourceMappings to collect read-only Lambda event source mapping evidence.",
                chargeable=False,
                evidence_categories=SQS_LAMBDA_POLLING_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lambda:ListEventSourceMappings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "SQS Lambda polling cost review requires cloudwatch:GetMetricData to collect read-only Lambda event source mapping evidence.",
                chargeable=False,
                evidence_categories=SQS_LAMBDA_POLLING_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricStatistics",
                "required",
                "SQS Lambda polling cost review requires cloudwatch:GetMetricStatistics to collect read-only Lambda event source mapping evidence.",
                chargeable=False,
                evidence_categories=SQS_LAMBDA_POLLING_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricStatistics is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
