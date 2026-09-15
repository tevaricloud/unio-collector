from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.aws.analytics.ai.athena_glue import AnalyticsAiAthenaGlueMixin
from unio_collector.aws.analytics.ai.helpers import AnalyticsAiHelperMixin
from unio_collector.aws.analytics.evidence.collector import NumericEvidenceCollector
from unio_collector.aws.analytics.evidence.compatibility import resolve_analytics_export
from unio_collector.aws.athena.query.scope import AthenaQueryCollectionScope
from unio_collector.aws.athena.region_record import AthenaRegionRecord
from unio_collector.aws.bedrock.operation_limitation import BedrockOperationLimitation
from unio_collector.aws.bedrock.region_record import BedrockRegionRecord
from unio_collector.aws.glue.job.scope import GlueJobCollectionScope
from unio_collector.aws.glue.region_record import GlueRegionRecord
from unio_collector.aws.inventory_helpers import (
    AwsInventoryValueHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.sagemaker.region_record import SageMakerRegionRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext

    AthenaQueryExecutionCollectionOptions: type[AthenaQueryCollectionScope]
    GlueJobRunCollectionOptions: type[GlueJobCollectionScope]


class AnalyticsAiInventoryCollector(AnalyticsAiAthenaGlueMixin, AnalyticsAiHelperMixin):
    """Collect read-only analytics and AI metadata for cost review scanners."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        athena_query_execution_options: AthenaQueryCollectionScope | None = None,
        glue_job_run_options: GlueJobCollectionScope | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.athena_query_execution_options = athena_query_execution_options or AthenaQueryCollectionScope()
        self.glue_job_run_options = glue_job_run_options or GlueJobCollectionScope()
        self._pagination = AwsPaginationHelper()
        self._values = AwsInventoryValueHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="AnalyticsAiInventoryCollector",
        )
        self._available_regions_cache: list[str] | None = None

    def collect_athena_records(self) -> list[AthenaRegionRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="athena",
            operation=("ListWorkGroups+GetWorkGroup+ListDataCatalogs+ListQueryExecutions+BatchGetQueryExecution"),
            collect_region=self._collect_athena_record,
        )

    def collect_glue_records(self) -> list[GlueRegionRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="glue",
            operation="GetCrawlers+GetJobs+GetJobRuns",
            collect_region=self._collect_glue_record,
        )

    def collect_sagemaker_records(self) -> list[SageMakerRegionRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="sagemaker",
            operation=("ListNotebookInstances+ListEndpoints+DescribeEndpoint+DescribeEndpointConfig+ListTrainingJobs"),
            collect_region=self._collect_sagemaker_record,
        )

    def collect_bedrock_records(self) -> list[BedrockRegionRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="bedrock",
            operation=("ListFoundationModels+ListCustomModels+ListProvisionedModelThroughputs+ListInferenceProfiles+ListKnowledgeBases"),
            collect_region=self._collect_bedrock_record,
        )

    def _collect_athena_record(self, region: str) -> list[AthenaRegionRecord]:
        permission_errors: list[str] = []
        client = self._safe_client("athena", region, permission_errors)
        if client is None:
            return [
                AthenaRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                    collection_evidence_version=1,
                ),
            ]

        workgroup_names = self._collect_athena_workgroup_names(
            client,
            permission_errors,
        )
        workgroups = [
            workgroup
            for workgroup_name in workgroup_names
            if (
                workgroup := self._get_athena_workgroup(
                    client,
                    workgroup_name,
                    permission_errors,
                )
            )
        ]

        data_catalogs = self._collect_athena_data_catalogs(
            client,
            permission_errors,
        )
        query_execution_summary = self._collect_athena_query_execution_summary(
            client,
            workgroup_names,
            permission_errors,
        )
        return [
            AthenaRegionRecord(
                account_id=self.account_id,
                region=region,
                workgroup_count=len(workgroup_names),
                unbounded_workgroup_count=sum(1 for workgroup in workgroups if self._is_workgroup_unbounded(workgroup)),
                enforced_workgroup_count=sum(1 for workgroup in workgroups if self._is_workgroup_enforced(workgroup)),
                metrics_enabled_workgroup_count=sum(1 for workgroup in workgroups if self._is_workgroup_metric_publishing_enabled(workgroup)),
                requester_pays_workgroup_count=sum(1 for workgroup in workgroups if self._is_workgroup_requester_pays_enabled(workgroup)),
                data_catalog_count=len(data_catalogs),
                sample_workgroup_names=self._limit_samples(workgroup_names),
                sample_data_catalog_names=self._limit_samples(
                    self._get_data_catalog_names(data_catalogs),
                ),
                query_execution_workgroups_checked=(query_execution_summary.workgroups_checked),
                query_execution_count=(query_execution_summary.query_execution_count),
                failed_query_execution_count=(query_execution_summary.failed_query_execution_count),
                collection_evidence_version=1,
                query_numeric_evidence=query_execution_summary.numeric_evidence,
                configured_query_duration=self.athena_query_execution_options.long_running_query_ms,
                configured_query_bytes=self.athena_query_execution_options.high_bytes_scanned,
                policy_input_source=self.athena_query_execution_options.policy_input_source,
                total_bytes_scanned=query_execution_summary.total_bytes_scanned,
                total_engine_execution_ms=(query_execution_summary.total_engine_execution_ms),
                query_execution_collection_limited=(query_execution_summary.collection_limited),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_glue_record(self, region: str) -> list[GlueRegionRecord]:
        permission_errors: list[str] = []
        client = self._safe_client("glue", region, permission_errors)
        if client is None:
            return [
                GlueRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                    collection_evidence_version=1,
                ),
            ]

        crawlers = self._collect_glue_crawlers(client, permission_errors)
        jobs = self._collect_glue_jobs(client, permission_errors)
        job_runs = self._collect_glue_job_run_summary(
            client,
            jobs,
            permission_errors,
        )
        numeric_jobs = NumericEvidenceCollector(2)
        for job in jobs:
            numeric_jobs.add(job.get("NumberOfWorkers"), job.get("MaxCapacity"))
        return [
            GlueRegionRecord(
                account_id=self.account_id,
                region=region,
                crawler_count=len(crawlers),
                scheduled_crawler_count=sum(1 for crawler in crawlers if self._has_schedule(crawler)),
                job_count=len(jobs),
                collection_evidence_version=1,
                job_numeric_evidence=numeric_jobs.finish(read_complete=not permission_errors),
                run_numeric_evidence=job_runs.numeric_evidence,
                configured_run_duration=self.glue_job_run_options.long_running_job_seconds,
                configured_run_dpu=self.glue_job_run_options.high_dpu_seconds,
                policy_input_source=self.glue_job_run_options.policy_input_source,
                total_configured_workers=sum(self._get_glue_configured_worker_count(job) for job in jobs),
                sample_crawler_names=self._limit_samples(
                    self._get_named_values(crawlers, "Name"),
                ),
                sample_job_names=self._limit_samples(
                    self._get_named_values(jobs, "Name"),
                ),
                sample_worker_types=self._limit_samples(
                    self._get_named_values(jobs, "WorkerType"),
                ),
                job_run_jobs_checked=job_runs.jobs_checked,
                job_run_count=job_runs.run_count,
                failed_job_run_count=job_runs.failed_run_count,
                total_dpu_seconds=job_runs.total_dpu_seconds,
                job_run_collection_limited=job_runs.collection_limited,
                permission_errors=permission_errors,
            ),
        ]

    def _collect_sagemaker_record(self, region: str) -> list[SageMakerRegionRecord]:
        permission_errors: list[str] = []
        client = self._safe_client("sagemaker", region, permission_errors)
        if client is None:
            return [
                SageMakerRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]

        notebooks = self._collect_token_items(
            client,
            "list_notebook_instances",
            "NotebookInstances",
            permission_errors,
        )
        endpoints = self._collect_token_items(
            client,
            "list_endpoints",
            "Endpoints",
            permission_errors,
        )
        endpoint_configs = self._collect_sagemaker_endpoint_configs(
            client,
            endpoints,
            permission_errors,
        )
        training_jobs = self._collect_token_items(
            client,
            "list_training_jobs",
            "TrainingJobSummaries",
            permission_errors,
        )
        processing_jobs = self._collect_token_items(
            client,
            "list_processing_jobs",
            "ProcessingJobSummaries",
            permission_errors,
        )
        transform_jobs = self._collect_token_items(
            client,
            "list_transform_jobs",
            "TransformJobSummaries",
            permission_errors,
        )
        return [
            SageMakerRegionRecord(
                account_id=self.account_id,
                region=region,
                notebook_count=len(notebooks),
                running_notebook_count=sum(1 for notebook in notebooks if self._is_sagemaker_notebook_running(notebook)),
                endpoint_count=len(endpoints),
                in_service_endpoint_count=sum(1 for endpoint in endpoints if self._is_sagemaker_endpoint_in_service(endpoint)),
                endpoint_variant_count=sum(len(self._get_sagemaker_endpoint_variants(config)) for config in endpoint_configs),
                provisioned_endpoint_instance_count=sum(self._get_sagemaker_endpoint_instance_count(config) for config in endpoint_configs),
                serverless_endpoint_variant_count=sum(self._get_sagemaker_serverless_variant_count(config) for config in endpoint_configs),
                async_endpoint_count=sum(1 for config in endpoint_configs if self._has_async_inference(config)),
                training_job_count=len(training_jobs),
                active_training_job_count=sum(1 for job in training_jobs if self._is_sagemaker_training_job_active(job)),
                processing_job_count=len(processing_jobs),
                active_processing_job_count=sum(1 for job in processing_jobs if self._is_sagemaker_processing_job_active(job)),
                transform_job_count=len(transform_jobs),
                active_transform_job_count=sum(1 for job in transform_jobs if self._is_sagemaker_transform_job_active(job)),
                sample_notebook_names=self._limit_samples(
                    self._get_named_values(notebooks, "NotebookInstanceName"),
                ),
                sample_endpoint_names=self._limit_samples(
                    self._get_named_values(endpoints, "EndpointName"),
                ),
                sample_endpoint_instance_types=self._limit_samples(
                    self._get_endpoint_instance_types(endpoint_configs),
                ),
                sample_training_job_names=self._limit_samples(
                    self._get_named_values(training_jobs, "TrainingJobName"),
                ),
                sample_processing_job_names=self._limit_samples(
                    self._get_named_values(processing_jobs, "ProcessingJobName"),
                ),
                sample_transform_job_names=self._limit_samples(
                    self._get_named_values(transform_jobs, "TransformJobName"),
                ),
                permission_errors=permission_errors,
            ),
        ]


__getattr__ = resolve_analytics_export

__all__ = [
    "AnalyticsAiInventoryCollector",
    "AthenaQueryExecutionCollectionOptions",
    "AthenaRegionRecord",
    "BedrockOperationLimitation",
    "BedrockRegionRecord",
    "GlueJobRunCollectionOptions",
    "GlueRegionRecord",
    "SageMakerRegionRecord",
]
