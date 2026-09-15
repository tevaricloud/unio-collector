from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

SERVERLESS_SCANNERS: dict[str, ScannerDefinition] = {
    "sqs-lambda-polling-cost-review": ScannerDefinition(
        scanner_id="sqs-lambda-polling-cost-review",
        display_name="SQS Lambda polling cost review",
        description=("Detects SQS event source mappings and available Lambda/SQS CloudWatch metrics for polling cost review."),
        aws_services=("AWS Lambda", "Amazon SQS", "Amazon CloudWatch"),
        resource_types=("Lambda event source mapping",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "lambda:ListEventSourceMappings",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "lambda:ListEventSourceMappings",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        risk_level="low",
        output_finding_types=("sqs_lambda_polling_cost_review",),
        maturity="experimental",
        limitations=(
            "Topology alone does not prove a cost issue.",
            "Metric availability depends on CloudWatch retention and permissions.",
            "max_mappings_per_region can bound mapping and metric coverage for faster development scans.",
        ),
        cloudwatch_namespaces_used=("AWS/Lambda", "AWS/SQS"),
        metrics_used=(
            "Invocations",
            "Errors",
            "Duration",
            "NumberOfMessagesReceived",
            "NumberOfEmptyReceives",
            "ApproximateAgeOfOldestMessage",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized SQS/Lambda mapping inventory evidence without AWS clients or runtime context."),
    ),
    "lambda-cost-cycle-risk-review": ScannerDefinition(
        scanner_id="lambda-cost-cycle-risk-review",
        display_name="Lambda cost and cycle-risk review",
        description=("Reviews Lambda functions, event sources, S3 notifications, metrics, and log ingestion for cost or repeated-execution risk signals."),
        aws_services=(
            "AWS Lambda",
            "Amazon S3",
            "Amazon CloudWatch",
            "Amazon CloudWatch Logs",
        ),
        resource_types=(
            "Lambda function",
            "S3 bucket notification",
            "CloudWatch log group",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "lambda:ListFunctions",
            "lambda:GetFunctionConfiguration",
            "lambda:ListTags",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:ListEventSourceMappings",
            "s3:ListAllMyBuckets",
            "s3:GetBucketNotification",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "lambda:ListFunctions",
            "lambda:GetFunctionConfiguration",
            "lambda:ListTags",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:ListEventSourceMappings",
            "s3:ListBuckets",
            "s3:GetBucketNotificationConfiguration",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        risk_level="medium",
        output_finding_types=("lambda_cost_cycle_risk_review",),
        maturity="experimental",
        limitations=(
            "Detects topology and metric signals but does not inspect application code.",
            "S3 cyclic trigger risk is suggestive unless write destinations are confirmed.",
            "Does not modify functions, triggers, concurrency, or alarms.",
            "collect_tags can be disabled for faster development scans, but Lambda tag context is omitted from cycle-risk evidence in that mode.",
            "s3_notification_detail_mode can be set to summary for faster development scans, but S3 trigger topology and possible cyclic-trigger findings require full detail.",  # noqa: E501
            "s3_policy_scan_max_functions is accepted for compatibility but no longer affects collection.",
        ),
        cloudwatch_namespaces_used=("AWS/Lambda", "AWS/Logs"),
        metrics_used=(
            "Invocations",
            "Duration",
            "Errors",
            "Throttles",
            "IncomingBytes",
        ),
        explanation=(
            "Reviews Lambda functions for invocation, error, duration, throttle, "
            "S3 trigger, and log-ingestion patterns that can create unexpected cost. "
            "It is advisory and does not alter Lambda or S3 configuration."
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized Lambda cycle-risk inventory evidence; "
            "coverage-note and summary side-channel writes are optional during "
            "strict replay."
        ),
    ),
}

SERVERLESS_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "serverless",
    SERVERLESS_SCANNERS,
)
