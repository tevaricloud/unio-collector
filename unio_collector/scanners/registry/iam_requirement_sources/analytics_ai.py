from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE = (
    "Athena workgroup",
    "Athena data catalog",
)

BEDROCK_COST_REVIEW_EVIDENCE = (
    "Bedrock model",
    "Bedrock agent",
    "Bedrock provisioned throughput",
    "Bedrock knowledge base",
    "Regional Bedrock service-availability context",
)

GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE = (
    "Glue crawler",
    "Glue job",
)

SAGEMAKER_COST_REVIEW_EVIDENCE = (
    "SageMaker notebook",
    "SageMaker endpoint",
    "SageMaker training job",
    "SageMaker processing job",
    "SageMaker transform job",
)

ANALYTICS_AI_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "athena-query-efficiency-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Athena query efficiency review requires ec2:DescribeRegions to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "athena:ListWorkGroups",
                "required",
                "Athena query efficiency review requires athena:ListWorkGroups to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="athena:ListWorkGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "athena:GetWorkGroup",
                "required",
                "Athena query efficiency review requires athena:GetWorkGroup to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="athena:GetWorkGroup is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "athena:ListDataCatalogs",
                "required",
                "Athena query efficiency review requires athena:ListDataCatalogs to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="athena:ListDataCatalogs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "athena:ListQueryExecutions",
                "required",
                "Athena query efficiency review requires athena:ListQueryExecutions to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="athena:ListQueryExecutions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "athena:BatchGetQueryExecution",
                "required",
                "Athena query efficiency review requires athena:BatchGetQueryExecution to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="athena:BatchGetQueryExecution is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Athena query efficiency review requires ce:GetCostAndUsage to collect read-only Athena workgroup, Athena data catalog evidence.",
                chargeable=False,
                evidence_categories=ATHENA_QUERY_EFFICIENCY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "bedrock-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Bedrock cost review requires ec2:DescribeRegions to collect read-only Bedrock model, Bedrock agent, "
                "Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock service-availability context "
                "evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListFoundationModels",
                "required",
                "Bedrock cost review requires bedrock:ListFoundationModels to collect read-only Bedrock model, "
                "Bedrock agent, Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock "
                "service-availability context evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListFoundationModels is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListCustomModels",
                "required",
                "Bedrock cost review requires bedrock:ListCustomModels to collect read-only Bedrock model, Bedrock "
                "agent, Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock "
                "service-availability context evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListCustomModels is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListProvisionedModelThroughputs",
                "required",
                "Bedrock cost review requires bedrock:ListProvisionedModelThroughputs to collect "
                "read-only Bedrock model, Bedrock agent, Bedrock provisioned throughput, Bedrock "
                "knowledge base, Regional Bedrock service-availability context evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListProvisionedModelThroughputs is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListInferenceProfiles",
                "required",
                "Bedrock cost review requires bedrock:ListInferenceProfiles to collect read-only Bedrock model, "
                "Bedrock agent, Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock "
                "service-availability context evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListInferenceProfiles is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListAgents",
                "required",
                "Bedrock cost review requires bedrock:ListAgents to collect read-only Bedrock model, Bedrock agent, "
                "Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock service-availability context "
                "evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListAgents is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "bedrock:ListKnowledgeBases",
                "required",
                "Bedrock cost review requires bedrock:ListKnowledgeBases to collect read-only Bedrock model, "
                "Bedrock agent, Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock "
                "service-availability context evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="bedrock:ListKnowledgeBases is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Bedrock cost review requires ce:GetCostAndUsage to collect read-only Bedrock model, Bedrock agent, "
                "Bedrock provisioned throughput, Bedrock knowledge base, Regional Bedrock service-availability context "
                "evidence.",
                chargeable=False,
                evidence_categories=BEDROCK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "glue-job-crawler-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Glue job and crawler cost review requires ec2:DescribeRegions to collect read-only Glue crawler, Glue job evidence.",
                chargeable=False,
                evidence_categories=GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "glue:GetCrawlers",
                "required",
                "Glue job and crawler cost review requires glue:GetCrawlers to collect read-only Glue crawler, Glue job evidence.",
                chargeable=False,
                evidence_categories=GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="glue:GetCrawlers is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "glue:GetJobs",
                "required",
                "Glue job and crawler cost review requires glue:GetJobs to collect read-only Glue crawler, Glue job evidence.",
                chargeable=False,
                evidence_categories=GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="glue:GetJobs is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "glue:GetJobRuns",
                "required",
                "Glue job and crawler cost review requires glue:GetJobRuns to collect read-only Glue crawler, Glue job evidence.",
                chargeable=False,
                evidence_categories=GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="glue:GetJobRuns is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Glue job and crawler cost review requires ce:GetCostAndUsage to collect read-only Glue crawler, Glue job evidence.",
                chargeable=False,
                evidence_categories=GLUE_JOB_CRAWLER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "sagemaker-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "SageMaker cost review requires ec2:DescribeRegions to collect read-only SageMaker notebook, SageMaker "
                "endpoint, SageMaker training job, SageMaker processing job, SageMaker transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:ListNotebookInstances",
                "required",
                "SageMaker cost review requires sagemaker:ListNotebookInstances to collect read-only "
                "SageMaker notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, "
                "SageMaker transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:ListNotebookInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:ListEndpoints",
                "required",
                "SageMaker cost review requires sagemaker:ListEndpoints to collect read-only SageMaker notebook, "
                "SageMaker endpoint, SageMaker training job, SageMaker processing job, SageMaker transform job "
                "evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:ListEndpoints is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:DescribeEndpoint",
                "required",
                "SageMaker cost review requires sagemaker:DescribeEndpoint to collect read-only SageMaker "
                "notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, SageMaker "
                "transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:DescribeEndpoint is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:DescribeEndpointConfig",
                "required",
                "SageMaker cost review requires sagemaker:DescribeEndpointConfig to collect read-only "
                "SageMaker notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, "
                "SageMaker transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:DescribeEndpointConfig is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:ListTrainingJobs",
                "required",
                "SageMaker cost review requires sagemaker:ListTrainingJobs to collect read-only SageMaker "
                "notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, SageMaker "
                "transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:ListTrainingJobs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:ListProcessingJobs",
                "required",
                "SageMaker cost review requires sagemaker:ListProcessingJobs to collect read-only SageMaker "
                "notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, SageMaker "
                "transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:ListProcessingJobs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sagemaker:ListTransformJobs",
                "required",
                "SageMaker cost review requires sagemaker:ListTransformJobs to collect read-only SageMaker "
                "notebook, SageMaker endpoint, SageMaker training job, SageMaker processing job, SageMaker "
                "transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sagemaker:ListTransformJobs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "SageMaker cost review requires ce:GetCostAndUsage to collect read-only SageMaker notebook, SageMaker "
                "endpoint, SageMaker training job, SageMaker processing job, SageMaker transform job evidence.",
                chargeable=False,
                evidence_categories=SAGEMAKER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
