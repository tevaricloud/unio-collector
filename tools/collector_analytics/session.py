"""Synthetic provider responses for actual Glue and SageMaker collection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticAnalyticsSession:
    """Drive real provider pagination and callbacks without SDK clients or network."""

    def __init__(self, service: str, variant: str) -> None:
        """Select one supported provider response shape for the real collector."""
        self.service = service
        self.variant = variant
        self.calls: list[str] = []
        self.collection_diagnostics = AwsCollectionDiagnostics()
        self.runtime_config = AwsRuntimeConfig(max_workers=1)

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticAnalyticsSession:
        """Return this isolated provider; unexpected service composition fails."""
        del audit_context
        if service_name != self.service or region_name != "eu-west-2":
            message = "Unexpected synthetic analytics service or region."
            raise ValueError(message)
        self.calls.append("create_client:" + service_name)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic unavailable"}}, "CreateClient")
        return self

    def can_paginate(self, _name: str) -> bool:
        """Use the actual supported one-page token-paginator fallback."""
        return False

    def _response(self, operation: str, key: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append(operation)
        fail = operation in {"get_job_runs", "list_training_jobs"}
        if fail and self.variant in {"denied", "unsupported", "failure"}:
            code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}[self.variant]
            raise ClientError({"Error": {"Code": code, "Message": "synthetic provider failure"}}, operation)
        if self.variant == "empty":
            rows = []
        if self.variant == "partial" and operation in {"get_jobs", "list_processing_jobs"}:
            return {key: None}
        return {key: rows}

    def get_crawlers(self, **_kwargs: object) -> dict[str, Any]:
        """Expose populated scheduled, unscheduled and nullable source metadata."""
        return self._response(
            "get_crawlers",
            "Crawlers",
            [
                {"Name": "synthetic-customer-crawler", "Schedule": {"ScheduleExpression": "cron(0 0 * * ? *)"}},
                {"Name": "synthetic-customer-crawler-two", "Schedule": None},
            ],
        )

    def get_jobs(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise complete numeric rows, nullable values and job selection caps."""
        jobs = [
            {"Name": "synthetic-customer-job", "WorkerType": "G.1X", "NumberOfWorkers": 4, "MaxCapacity": 2.5},
            {"Name": "synthetic-customer-job-two", "WorkerType": "CUSTOM-WORKER", "MaxCapacity": 3.0},
        ]
        if self.variant == "nullable":
            jobs = [{"Name": "synthetic-customer-job", "WorkerType": None, "NumberOfWorkers": None, "MaxCapacity": None}]
        if self.variant == "malformed":
            jobs[0].update(NumberOfWorkers=True, MaxCapacity=float("inf"))
        return self._response("get_jobs", "Jobs", jobs)

    def get_job_runs(self, **_kwargs: object) -> dict[str, Any]:
        """Return actual provider numbers/statuses rather than a rewritten DTO."""
        rows: list[dict[str, Any]] = [
            {"JobRunState": "FAILED", "ExecutionTime": 300, "JobRunQueuingDuration": 12, "DPUSeconds": 120.5},
            {"JobRunState": "SUCCEEDED", "ExecutionTime": 25, "DPUSeconds": 10.0},
        ]
        if self.variant == "nullable":
            rows = [{"JobRunState": None, "ExecutionTime": None, "DPUSeconds": None}]
        if self.variant == "malformed":
            rows[0].update(ExecutionTime="not-a-number", DPUSeconds=float("nan"))
        if self.variant == "omitted":
            rows = rows * 1100
        result = self._response("get_job_runs", "JobRuns", rows)
        if self.variant == "capped":
            result["NextToken"] = "synthetic-next"
        return result

    def list_notebook_instances(self, **_kwargs: object) -> dict[str, Any]:
        """Retain actual active/inactive status interpretation and customer names."""
        return self._response(
            "list_notebook_instances",
            "NotebookInstances",
            [
                {"NotebookInstanceName": "synthetic-customer-notebook", "NotebookInstanceStatus": "InService"},
                {"NotebookInstanceName": "synthetic-customer-stopped", "NotebookInstanceStatus": None},
            ],
        )

    def list_endpoints(self, **_kwargs: object) -> dict[str, Any]:
        """Include populated endpoints and the source-supported empty name case."""
        return self._response(
            "list_endpoints",
            "Endpoints",
            [{"EndpointName": "synthetic-customer-endpoint", "EndpointStatus": "InService"}, {"EndpointName": None, "EndpointStatus": "Failed"}],
        )

    def describe_endpoint(self, **_kwargs: object) -> dict[str, Any]:
        """Drive the actual dependent endpoint-config lookup."""
        self.calls.append("describe_endpoint")
        return {"EndpointConfigName": None if self.variant == "nullable" else "synthetic-customer-config"}

    def describe_endpoint_config(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise provisioned, serverless, asynchronous and nullable branches."""
        self.calls.append("describe_endpoint_config")
        return {
            "ProductionVariants": [
                {"InstanceType": "ml.m5.large", "InitialInstanceCount": 2},
                {"InstanceType": "synthetic-customer-instance", "ServerlessConfig": {"MemorySizeInMB": 2048}},
            ],
            "AsyncInferenceConfig": {"OutputConfig": {"S3OutputPath": "s3://synthetic-customer-output/"}},
        }

    def list_training_jobs(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise active and stopped real training summaries."""
        return self._response(
            "list_training_jobs",
            "TrainingJobSummaries",
            [
                {"TrainingJobName": "synthetic-customer-training", "TrainingJobStatus": "InProgress"},
                {"TrainingJobName": "synthetic-customer-training-two", "TrainingJobStatus": "Completed"},
            ],
        )

    def list_processing_jobs(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise processing counts, nullable status and malformed response branch."""
        return self._response(
            "list_processing_jobs",
            "ProcessingJobSummaries",
            [
                {"ProcessingJobName": "synthetic-customer-processing", "ProcessingJobStatus": "Stopping"},
                {"ProcessingJobName": "synthetic-customer-processing-two", "ProcessingJobStatus": None},
            ],
        )

    def list_transform_jobs(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise the supported active and failed transform status branches."""
        return self._response(
            "list_transform_jobs",
            "TransformJobSummaries",
            [
                {"TransformJobName": "synthetic-customer-transform", "TransformJobStatus": "InProgress"},
                {"TransformJobName": "synthetic-customer-transform-two", "TransformJobStatus": "Failed"},
            ],
        )
