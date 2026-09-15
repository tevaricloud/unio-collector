from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

OBSERVABILITY_SCANNERS: dict[str, ScannerDefinition] = {
    "cloudwatch-log-groups-without-retention": ScannerDefinition(
        scanner_id="cloudwatch-log-groups-without-retention",
        display_name="CloudWatch Log Groups without retention",
        description="Finds CloudWatch Log Groups that do not have an explicit retentionInDays setting.",
        aws_services=("Amazon CloudWatch Logs",),
        resource_types=("CloudWatch Log Group",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=("logs:DescribeLogGroups",),
        required_permission_level="read_only",
        aws_api_calls=("logs:DescribeLogGroups",),
        risk_level="low",
        output_finding_types=("cloudwatch_logs_infinite_retention",),
        maturity="basic",
        execution_phase="dependent",
        depends_on_scanner_ids=("cloudwatch-idle-log-review",),
        limitations=(
            "Does not determine compliance retention requirements.",
            "Does not change log retention settings.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Carries CloudWatch Logs retention records and scanned regions in serialized evidence for offline analysis."),
    ),
    "cloudwatch-idle-log-review": ScannerDefinition(
        scanner_id="cloudwatch-idle-log-review",
        display_name="CloudWatch idle log review",
        description="Reviews log groups for low recent ingestion, stored bytes, and retention context.",
        aws_services=("Amazon CloudWatch Logs", "Amazon CloudWatch"),
        resource_types=("CloudWatch Log Group",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "logs:DescribeLogGroups",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "logs:DescribeLogGroups",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        risk_level="low",
        output_finding_types=("cloudwatch_idle_log_review",),
        maturity="experimental",
        limitations=(
            "Uses available CloudWatch ingestion metrics for the selected window.",
            "Does not delete log groups or change retention.",
            "Does not prove compliance retention requirements.",
        ),
        cloudwatch_namespaces_used=("AWS/Logs",),
        metrics_used=("IncomingBytes", "IncomingLogEvents"),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Carries CloudWatch Logs activity records, scanned regions, and idle-day threshold in serialized evidence for offline analysis."
        ),
    ),
    "cloudwatch-log-cost-and-relevance-review": ScannerDefinition(
        scanner_id="cloudwatch-log-cost-and-relevance-review",
        display_name="CloudWatch log cost and relevance review",
        description="Reviews log ingestion, stored bytes, and retention as cost relevance signals.",
        aws_services=("Amazon CloudWatch Logs", "Amazon CloudWatch"),
        resource_types=("CloudWatch Log Group",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "logs:DescribeLogGroups",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "logs:DescribeLogGroups",
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
        ),
        risk_level="low",
        output_finding_types=("cloudwatch_log_cost_and_relevance_review",),
        maturity="experimental",
        execution_phase="dependent",
        depends_on_scanner_ids=("cloudwatch-idle-log-review",),
        limitations=("Does not delete logs or decide compliance retention.",),
        cloudwatch_namespaces_used=("AWS/Logs",),
        metrics_used=("IncomingBytes", "IncomingLogEvents"),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Reuses serialized CloudWatch Logs activity evidence and derives cost/relevance findings without AWS clients."),
    ),
    "xray-tracing-cost-governance-review": ScannerDefinition(
        scanner_id="xray-tracing-cost-governance-review",
        display_name="X-Ray tracing cost governance review",
        description=(
            "Reviews X-Ray groups, sampling rules, sampling statistic summaries, "
            "encryption metadata, and cached Cost Explorer spend as tracing cost "
            "governance signals."
        ),
        aws_services=("AWS X-Ray", "AWS Cost Explorer"),
        resource_types=(
            "X-Ray group",
            "X-Ray sampling rule",
            "X-Ray sampling statistic summary",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "xray:GetGroups",
            "xray:GetSamplingRules",
            "xray:GetSamplingStatisticSummaries",
            "xray:GetEncryptionConfig",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "xray:GetGroups",
            "xray:GetSamplingRules",
            "xray:GetSamplingStatisticSummaries",
            "xray:GetEncryptionConfig",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("xray_tracing_cost_governance_review",),
        maturity="experimental",
        limitations=(
            "Does not retrieve trace documents or inspect application payloads.",
            "Does not disable tracing, change groups, or change sampling rules.",
            ("Exact application or resource-level trace cost attribution requires billing exports, application telemetry, or owner validation."),
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects X-Ray inventory and cost signal evidence during collection and analyzes only serialized X-Ray evidence without AWS clients."
        ),
    ),
}

OBSERVABILITY_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "observability",
    OBSERVABILITY_SCANNERS,
)
