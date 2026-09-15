# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.aws.analytics.evidence.collector import NumericEvidenceCollector
from unio_collector.aws.analytics.evidence.response import collect_analytics_page_rows
from unio_collector.aws.athena.query.summary import AthenaQueryExecutionSummary
from unio_collector.aws.bedrock.region_record import BedrockRegionRecord
from unio_collector.aws.glue.job.summary import GlueJobRunSummary

if TYPE_CHECKING:
    from unio_collector.aws.athena.query.scope import AthenaQueryCollectionScope
    from unio_collector.aws.bedrock.operation_limitation import (
        BedrockOperationLimitation,
    )
    from unio_collector.aws.glue.job.scope import GlueJobCollectionScope


class AnalyticsAiAthenaGlueMixin:  # noqa: D101
    def _collect_bedrock_record(self, region: str) -> list[BedrockRegionRecord]:
        permission_errors: list[str] = []
        operation_limitations: list[BedrockOperationLimitation] = []
        client = self._safe_client("bedrock", region, permission_errors)
        agent_client = self._safe_client("bedrock-agent", region, permission_errors)
        if client is None and agent_client is None:
            return [
                BedrockRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]

        foundation_models = (
            self._collect_token_items(
                client,
                "list_foundation_models",
                "modelSummaries",
                permission_errors,
            )
            if client is not None
            else []
        )
        custom_models = (
            self._collect_bedrock_token_items(
                client,
                "list_custom_models",
                "ListCustomModels",
                "modelSummaries",
                permission_errors,
                operation_limitations,
            )
            if client is not None
            else []
        )
        provisioned_models = (
            self._collect_token_items(
                client,
                "list_provisioned_model_throughputs",
                "provisionedModelSummaries",
                permission_errors,
            )
            if client is not None
            else []
        )
        inference_profiles = (
            self._collect_token_items(
                client,
                "list_inference_profiles",
                "inferenceProfileSummaries",
                permission_errors,
            )
            if client is not None
            else []
        )
        knowledge_bases = (
            self._collect_token_items(
                agent_client,
                "list_knowledge_bases",
                "knowledgeBaseSummaries",
                permission_errors,
            )
            if agent_client is not None
            else []
        )
        agents = (
            self._collect_token_items(
                agent_client,
                "list_agents",
                "agentSummaries",
                permission_errors,
            )
            if agent_client is not None
            else []
        )
        return [
            BedrockRegionRecord(
                account_id=self.account_id,
                region=region,
                foundation_model_count=len(foundation_models),
                custom_model_count=len(custom_models),
                provisioned_throughput_count=len(provisioned_models),
                inference_profile_count=len(inference_profiles),
                agent_count=len(agents),
                knowledge_base_count=len(knowledge_bases),
                sample_foundation_model_ids=self._limit_samples(
                    self._get_named_values(foundation_models, "modelId"),
                ),
                sample_custom_model_names=self._limit_samples(
                    self._get_bedrock_names(custom_models),
                ),
                sample_provisioned_model_names=self._limit_samples(
                    self._get_bedrock_names(provisioned_models),
                ),
                sample_inference_profile_names=self._limit_samples(
                    self._get_bedrock_names(inference_profiles),
                ),
                sample_agent_names=self._limit_samples(self._get_bedrock_names(agents)),
                sample_knowledge_base_names=self._limit_samples(
                    self._get_bedrock_names(knowledge_bases),
                ),
                permission_errors=permission_errors,
                operation_limitations=operation_limitations,
            ),
        ]

    def _collect_athena_workgroup_names(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_work_groups",
                result_key="WorkGroups",
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="list_work_groups",
                exc=exc,
                require_evidence=True,
            )
            return []
        names: list[str] = []
        if not result.pages:
            permission_errors.append("list_work_groups:UnavailableEvidence")
        for page in result.pages:
            items = page.get("WorkGroups")
            if not isinstance(items, list):
                permission_errors.append("list_work_groups:UnavailableEvidence")
                continue
            for item in items:
                if isinstance(item, dict) and item.get("Name"):
                    names.append(str(item["Name"]))
                elif isinstance(item, str):
                    names.append(item)
                else:
                    permission_errors.append("list_work_groups:MalformedEvidence")
        return names

    def _get_athena_workgroup(
        self,
        client: Any,  # noqa: ANN401
        workgroup_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.get_work_group(WorkGroup=workgroup_name)
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="get_work_group",
                exc=exc,
                require_evidence=True,
            )
            return None
        workgroup = response.get("WorkGroup") if isinstance(response, dict) else None
        if not isinstance(workgroup, dict) or not isinstance(workgroup.get("Configuration"), dict):
            permission_errors.append("get_work_group:UnavailableEvidence")
        return workgroup if isinstance(workgroup, dict) else None

    def _collect_athena_data_catalogs(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_data_catalogs",
                result_key="DataCatalogsSummary",
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="list_data_catalogs",
                exc=exc,
                require_evidence=True,
            )
            return []
        return collect_analytics_page_rows(result.pages, "DataCatalogsSummary", permission_errors, "list_data_catalogs")

    def _collect_athena_query_execution_summary(
        self,
        client: Any,  # noqa: ANN401
        workgroup_names: list[str],
        permission_errors: list[str],
    ) -> AthenaQueryExecutionSummary:
        if not hasattr(client, "list_query_executions") or not hasattr(
            client,
            "batch_get_query_execution",
        ):
            permission_errors.append("list_query_executions:UnsupportedClientMethod")
            return AthenaQueryExecutionSummary()

        options = self.athena_query_execution_options
        selected_workgroups = workgroup_names[: options.max_query_execution_workgroups]
        collection_limited = len(workgroup_names) > len(selected_workgroups)
        query_executions: list[dict[str, Any]] = []
        for workgroup_name in selected_workgroups:
            ids, has_more = self._collect_athena_query_execution_ids(
                client,
                workgroup_name,
                options,
                permission_errors,
            )
            collection_limited = collection_limited or has_more
            if not ids:
                continue
            query_executions.extend(
                self._collect_athena_query_executions(
                    client,
                    ids,
                    permission_errors,
                ),
            )

        numeric_queries = NumericEvidenceCollector(3)
        for execution in query_executions:
            statistics = self._get_athena_query_statistics(execution)
            numeric_queries.add(
                statistics.get("TotalExecutionTimeInMillis"),
                statistics.get("EngineExecutionTimeInMillis"),
                statistics.get("DataScannedInBytes"),
            )
        return AthenaQueryExecutionSummary(
            workgroups_checked=len(selected_workgroups),
            query_execution_count=len(query_executions),
            failed_query_execution_count=sum(1 for execution in query_executions if self._is_failed_athena_query(execution)),
            numeric_evidence=numeric_queries.finish(read_complete=not permission_errors),
            total_bytes_scanned=sum(self._get_athena_query_bytes_scanned(execution) for execution in query_executions),
            total_engine_execution_ms=sum(
                self._get_int(
                    self._get_athena_query_statistics(execution).get(
                        "EngineExecutionTimeInMillis",
                    ),
                )
                for execution in query_executions
            ),
            collection_limited=collection_limited,
        )

    def _collect_athena_query_execution_ids(
        self,
        client: Any,  # noqa: ANN401
        workgroup_name: str,
        options: AthenaQueryCollectionScope,
        permission_errors: list[str],
    ) -> tuple[list[str], bool]:
        try:
            response = client.list_query_executions(
                WorkGroup=workgroup_name,
                MaxResults=options.max_query_executions_per_workgroup,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="list_query_executions",
                exc=exc,
                require_evidence=True,
            )
            return [], False
        ids = response.get("QueryExecutionIds") if isinstance(response, dict) else None
        if not isinstance(ids, list):
            permission_errors.append("list_query_executions:UnavailableEvidence")
            return [], bool(response.get("NextToken")) if isinstance(response, dict) else False
        if any(not isinstance(query_id, str) or not query_id for query_id in ids):
            permission_errors.append("list_query_executions:MalformedEvidence")
        return [str(query_id) for query_id in ids if query_id], bool(
            response.get("NextToken"),
        )

    def _collect_athena_query_executions(
        self,
        client: Any,  # noqa: ANN401
        query_execution_ids: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            response = client.batch_get_query_execution(
                QueryExecutionIds=query_execution_ids[:50],
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="batch_get_query_execution",
                exc=exc,
                require_evidence=True,
            )
            return []
        executions = response.get("QueryExecutions") if isinstance(response, dict) else None
        if not isinstance(executions, list):
            permission_errors.append("batch_get_query_execution:UnavailableEvidence")
            return []
        requested = set(query_execution_ids[:50])
        returned = [execution.get("QueryExecutionId") for execution in executions if isinstance(execution, dict)]
        if (
            len(returned) != len(executions)
            or len(returned) != len(requested)
            or any(not isinstance(value, str) or value not in requested for value in returned)
        ):
            permission_errors.append("batch_get_query_execution:PartialEvidence")
        if len({value for value in returned if isinstance(value, str)}) != len(requested) or response.get("UnprocessedQueryExecutionIds"):
            permission_errors.append("batch_get_query_execution:UnprocessedEvidence")
        return [execution for execution in executions if isinstance(execution, dict)]

    def _collect_glue_crawlers(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "get_crawlers",
                result_key="Crawlers",
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="get_crawlers",
                exc=exc,
                require_evidence=True,
            )
            return []
        return collect_analytics_page_rows(result.pages, "Crawlers", permission_errors, "get_crawlers")

    def _collect_glue_jobs(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "get_jobs",
                result_key="Jobs",
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="get_jobs",
                exc=exc,
                require_evidence=True,
            )
            return []
        return collect_analytics_page_rows(result.pages, "Jobs", permission_errors, "get_jobs")

    def _collect_glue_job_run_summary(
        self,
        client: Any,  # noqa: ANN401
        jobs: list[dict[str, Any]],
        permission_errors: list[str],
    ) -> GlueJobRunSummary:
        if not hasattr(client, "get_job_runs"):
            permission_errors.append("get_job_runs:UnsupportedClientMethod")
            return GlueJobRunSummary()

        options = self.glue_job_run_options
        job_names = self._get_named_values(jobs, "Name")
        selected_job_names = job_names[: options.max_job_run_jobs]
        collection_limited = len(job_names) > len(selected_job_names)
        runs: list[dict[str, Any]] = []
        for job_name in selected_job_names:
            page = self._get_glue_job_runs_page(
                client,
                job_name,
                options,
                permission_errors,
            )
            if not page:
                continue
            runs.extend(self._collect_items([page], "JobRuns"))
            collection_limited = collection_limited or bool(page.get("NextToken"))

        numeric_runs = NumericEvidenceCollector(3)
        for run in runs:
            numeric_runs.add(run.get("ExecutionTime"), run.get("JobRunQueuingDuration"), run.get("DPUSeconds"))
        return GlueJobRunSummary(
            jobs_checked=len(selected_job_names),
            run_count=len(runs),
            failed_run_count=sum(1 for run in runs if self._is_failed_glue_run(run)),
            numeric_evidence=numeric_runs.finish(read_complete=not permission_errors),
            total_dpu_seconds=sum(self._get_float(run.get("DPUSeconds")) for run in runs),
            collection_limited=collection_limited,
        )

    def _get_glue_job_runs_page(
        self,
        client: Any,  # noqa: ANN401
        job_name: str,
        options: GlueJobCollectionScope,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.get_job_runs(
                JobName=job_name,
                MaxResults=options.max_job_runs_per_job,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="get_job_runs",
                exc=exc,
                require_evidence=True,
            )
            return None
        if not isinstance(response, dict) or not isinstance(response.get("JobRuns"), list):
            permission_errors.append("get_job_runs:UnavailableEvidence")
            return None
        if any(not isinstance(run, dict) for run in response["JobRuns"]):
            permission_errors.append("get_job_runs:MalformedEvidence")
        return response
