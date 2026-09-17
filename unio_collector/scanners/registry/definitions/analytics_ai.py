from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

ANALYTICS_AI_SCANNERS: dict[str, ScannerDefinition] = {
    "athena-query-efficiency-review": ScannerDefinition(
        scanner_id="athena-query-efficiency-review",
        display_name="Athena query efficiency review",
        description=(
            "Reviews Athena workgroup query controls, metric publishing, "
            "requester-pays settings, data catalog footprint, and capped "
            "recent query-execution metadata as usage-based analytics cost "
            "signals."
        ),
        aws_services=(
            "Amazon Athena",
            "AWS Glue Data Catalog",
            "Amazon CloudWatch",
            "AWS Cost Explorer",
        ),
        resource_types=("Athena workgroup", "Athena data catalog"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "athena:ListWorkGroups",
            "athena:GetWorkGroup",
            "athena:ListDataCatalogs",
            "athena:ListQueryExecutions",
            "athena:BatchGetQueryExecution",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "athena:ListWorkGroups",
            "athena:GetWorkGroup",
            "athena:ListDataCatalogs",
            "athena:ListQueryExecutions",
            "athena:BatchGetQueryExecution",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("athena_query_efficiency_review",),
        maturity="experimental",
        limitations=(
            "Does not execute Athena queries or inspect table contents.",
            (
                "Collects capped recent query-execution metadata only; query "
                "text, table partitioning, storage format, and exact "
                "workgroup-level billing attribution remain out of scope."
            ),
            (
                "Correlates service and region-level Cost Explorer billing "
                "context where available; it does not attribute spend to "
                "individual workgroups or queries."
            ),
            "Does not recommend changing query controls without data owner validation.",
        ),
        cloudwatch_namespaces_used=("AWS/Athena",),
        metrics_used=("ProcessedBytes", "TotalExecutionTime", "QueryCount"),
        may_incur_charges=False,
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Athena workgroup, data catalog, capped query execution, "
            "and cost-context records during collection and analyzes only "
            "serialized Athena evidence without AWS clients."
        ),
    ),
    "glue-job-crawler-cost-review": ScannerDefinition(
        scanner_id="glue-job-crawler-cost-review",
        display_name="Glue job and crawler cost review",
        description=(
            "Reviews Glue crawler schedules, job capacity settings, worker metadata, and data platform ownership signals without starting jobs or crawlers."
        ),
        aws_services=("AWS Glue", "Amazon CloudWatch", "AWS Cost Explorer"),
        resource_types=("Glue crawler", "Glue job"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "glue:GetCrawlers",
            "glue:GetJobs",
            "glue:GetJobRuns",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "glue:GetCrawlers",
            "glue:GetJobs",
            "glue:GetJobRuns",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("glue_job_crawler_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not start Glue jobs or crawlers.",
            (
                "Collects capped recent job-run metadata only; full historical "
                "job-run history, input data volume, trigger graph, and exact "
                "job-level billing attribution remain out of scope."
            ),
            ("Correlates service and region-level Cost Explorer billing context where available; it does not attribute spend to individual jobs or crawlers."),
            "Does not recommend changing schedules or capacity without data platform owner validation.",
        ),
        cloudwatch_namespaces_used=("AWS/Glue",),
        metrics_used=(
            "glue.driver.aggregate.elapsedTime",
            "glue.driver.aggregate.numCompletedTasks",
        ),
        may_incur_charges=False,
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Glue crawler, job, capped job-run, and cost-context records "
            "during collection and analyzes only serialized Glue evidence without "
            "AWS clients."
        ),
    ),
    "sagemaker-cost-review": ScannerDefinition(
        scanner_id="sagemaker-cost-review",
        display_name="SageMaker cost review",
        description=(
            "Reviews SageMaker notebook, endpoint, endpoint configuration, training, processing, and transform job metadata as AI and ML platform cost signals."
        ),
        aws_services=("Amazon SageMaker", "Amazon CloudWatch", "AWS Cost Explorer"),
        resource_types=(
            "SageMaker notebook",
            "SageMaker endpoint",
            "SageMaker training job",
            "SageMaker processing job",
            "SageMaker transform job",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "sagemaker:ListNotebookInstances",
            "sagemaker:ListEndpoints",
            "sagemaker:DescribeEndpoint",
            "sagemaker:DescribeEndpointConfig",
            "sagemaker:ListTrainingJobs",
            "sagemaker:ListProcessingJobs",
            "sagemaker:ListTransformJobs",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "sagemaker:ListNotebookInstances",
            "sagemaker:ListEndpoints",
            "sagemaker:DescribeEndpoint",
            "sagemaker:DescribeEndpointConfig",
            "sagemaker:ListTrainingJobs",
            "sagemaker:ListProcessingJobs",
            "sagemaker:ListTransformJobs",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("sagemaker_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not start, stop, delete, resize, or change SageMaker resources.",
            "Does not collect endpoint invocation metrics, notebook CPU/GPU utilization, model accuracy, training job duration, or exact resource-level billing attribution.",  # noqa: E501
            (
                "Correlates service and region-level Cost Explorer billing "
                "context where available; it does not attribute spend to "
                "individual notebooks, endpoints, or jobs."
            ),
            "Does not infer idle endpoints or notebooks without owner and usage evidence.",
        ),
        cloudwatch_namespaces_used=("AWS/SageMaker",),
        metrics_used=(
            "Invocations",
            "ModelLatency",
            "CPUUtilization",
            "GPUUtilization",
        ),
        may_incur_charges=False,
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects SageMaker resource and cost-context records during collection and analyzes only serialized SageMaker evidence without AWS clients."
        ),
    ),
    "bedrock-cost-review": ScannerDefinition(
        scanner_id="bedrock-cost-review",
        display_name="Bedrock cost review",
        description=(
            "Reviews Bedrock custom model, provisioned throughput, agent, and "
            "knowledge base metadata as AI usage cost-governance signals. "
            "Foundation model and inference profile visibility is retained as "
            "regional service-availability context."
        ),
        aws_services=("Amazon Bedrock", "AWS Cost Explorer"),
        resource_types=(
            "Bedrock model",
            "Bedrock agent",
            "Bedrock provisioned throughput",
            "Bedrock knowledge base",
            "Regional Bedrock service-availability context",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "bedrock:ListFoundationModels",
            "bedrock:ListCustomModels",
            "bedrock:ListProvisionedModelThroughputs",
            "bedrock:ListInferenceProfiles",
            "bedrock:ListAgents",
            "bedrock:ListKnowledgeBases",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "bedrock:ListFoundationModels",
            "bedrock:ListCustomModels",
            "bedrock:ListProvisionedModelThroughputs",
            "bedrock:ListInferenceProfiles",
            "bedrock-agent:ListAgents",
            "bedrock-agent:ListKnowledgeBases",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("bedrock_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not invoke Bedrock models, agents, knowledge bases, or embedding workflows.",
            "Does not collect token counts, prompt contents, model invocation logs, knowledge-base ingestion volume, or exact resource-level billing attribution.",  # noqa: E501
            (
                "Correlates service and region-level Cost Explorer billing "
                "context where available; it does not attribute spend to "
                "individual model invocations or knowledge-base workflows."
            ),
            "Does not infer inefficient model usage from metadata alone.",
            "Does not create findings from regional foundation model or inference profile catalogue visibility alone.",
        ),
        cloudwatch_namespaces_used=("AWS/Bedrock",),
        metrics_used=("Invocations", "InputTokenCount", "OutputTokenCount"),
        may_incur_charges=False,
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Bedrock resource and cost-context records during collection and analyzes only serialized Bedrock evidence without AWS clients."
        ),
    ),
}

ANALYTICS_AI_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "analytics_ai",
    ANALYTICS_AI_SCANNERS,
)
