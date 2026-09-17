from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    AwsCollectionTaskResult,
    record_collection_results,
)
from unio_collector.aws.ecs.service.arns import EcsServiceArnCollection
from unio_collector.aws.ecs.service.details import EcsServiceDetailCollection


class ManagedPlatformEcsApiMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_ecs_cluster_arns(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_clusters",
                result_key="clusterArns",
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_clusters",
                exc=exc,
            )
            return []
        return [str(cluster_arn) for page in result.pages for cluster_arn in page.get("clusterArns", []) if cluster_arn]

    def _describe_ecs_clusters(
        self,
        client: Any,  # noqa: ANN401
        cluster_arns: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        clusters: list[dict[str, Any]] = []
        for cluster_batch in self._collector._chunk_values(cluster_arns, 100):  # noqa: SLF001
            try:
                response = client.describe_clusters(
                    clusters=cluster_batch,
                    include=["TAGS", "SETTINGS"],
                )
            except Exception as exc:  # noqa: BLE001
                self._collector._record_collection_error(  # noqa: SLF001
                    permission_errors,
                    method_name="describe_clusters",
                    exc=exc,
                )
                continue
            clusters.extend(
                self._collector._collect_response_items(response, "clusters"),  # noqa: SLF001
            )
        return clusters

    def _collect_ecs_service_arns(
        self,
        client: Any,  # noqa: ANN401
        cluster_arn: str,
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_services",
                result_key="serviceArns",
                request_parameters={"cluster": cluster_arn},
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_services",
                exc=exc,
            )
            return []
        return [str(service_arn) for page in result.pages for service_arn in page.get("serviceArns", []) if service_arn]

    def _collect_ecs_service_arns_by_cluster(
        self,
        client: Any,  # noqa: ANN401
        cluster_arns: list[str],
        permission_errors: list[str],
    ) -> dict[str, list[str]]:
        tasks = [
            AwsCollectionTask(
                name=(f"ManagedPlatformInventoryCollector:ecs-list-services:{cluster_arn}"),
                scanner_id=self._collector.audit_context.scanner_id,
                collector_id=self._collector.audit_context.collector,
                account_id=self._collector.account_id,
                region=self._collector._extract_region_from_arn(cluster_arn),  # noqa: SLF001
                service="ecs",
                operation="ListServices",
                payload={"cluster_arn": cluster_arn},
                collect=lambda cluster_arn=cluster_arn: self._collector._collect_ecs_service_arn_collection(  # noqa: SLF001
                    client,
                    cluster_arn,
                ),
            )
            for cluster_arn in cluster_arns
        ]
        results = AwsCollectionExecutor(
            max_workers=self._collector._get_max_workers(),  # noqa: SLF001
        ).run(tasks)
        record_collection_results(self._collector.session, results)
        service_arns_by_cluster: dict[str, list[str]] = {cluster_arn: [] for cluster_arn in cluster_arns}
        for result in results:
            cluster_arn = str(result.task.payload.get("cluster_arn") or "")
            if result.status == "completed" and result.value is not None:
                service_arns_by_cluster[cluster_arn] = list(result.value.service_arns)
                self._collector._extend_unique(  # noqa: SLF001
                    permission_errors,
                    result.value.permission_errors,
                )
                continue
            if result.error_code:
                self._collector._extend_unique(  # noqa: SLF001
                    permission_errors,
                    [f"list_services:{result.error_code}"],
                )
        return service_arns_by_cluster

    def _collect_ecs_service_arn_collection(
        self,
        client: Any,  # noqa: ANN401
        cluster_arn: str,
    ) -> EcsServiceArnCollection:
        permission_errors: list[str] = []
        return EcsServiceArnCollection(
            cluster_arn=cluster_arn,
            service_arns=self._collector._collect_ecs_service_arns(  # noqa: SLF001
                client,
                cluster_arn,
                permission_errors,
            ),
            permission_errors=permission_errors,
        )

    def _describe_ecs_services(
        self,
        client: Any,  # noqa: ANN401
        cluster_arn: str,
        service_arns: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        services: list[dict[str, Any]] = []
        for service_batch in self._collector._chunk_values(service_arns, 10):  # noqa: SLF001
            try:
                response = client.describe_services(
                    cluster=cluster_arn,
                    services=service_batch,
                    include=["TAGS"],
                )
            except Exception as exc:  # noqa: BLE001
                self._collector._record_collection_error(  # noqa: SLF001
                    permission_errors,
                    method_name="describe_services",
                    exc=exc,
                )
                continue
            services.extend(
                {
                    **service,
                    "__ClusterArn": cluster_arn,
                    "__ClusterName": cluster_arn.rsplit("/", 1)[-1],
                }
                for service in self._collector._collect_response_items(  # noqa: SLF001
                    response,
                    "services",
                )
            )
        return services

    def _describe_ecs_services_by_cluster(
        self,
        client: Any,  # noqa: ANN401
        service_arns_by_cluster: dict[str, list[str]],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        tasks: list[AwsCollectionTask[EcsServiceDetailCollection]] = []
        for cluster_arn, service_arns in service_arns_by_cluster.items():
            tasks.extend(
                AwsCollectionTask(
                    name=(f"ManagedPlatformInventoryCollector:ecs-describe-services:{cluster_arn}"),
                    scanner_id=self._collector.audit_context.scanner_id,
                    collector_id=self._collector.audit_context.collector,
                    account_id=self._collector.account_id,
                    region=self._collector._extract_region_from_arn(cluster_arn),  # noqa: SLF001
                    service="ecs",
                    operation="DescribeServices",
                    payload={
                        "cluster_arn": cluster_arn,
                        "service_count": len(service_batch),
                    },
                    collect=(
                        lambda cluster_arn=cluster_arn, service_batch=service_batch: self._collector._describe_ecs_service_collection(  # noqa: SLF001
                            client,
                            cluster_arn,
                            service_batch,
                        )
                    ),
                )
                for service_batch in self._collector._chunk_values(service_arns, 10)  # noqa: SLF001
            )
        results = AwsCollectionExecutor(
            max_workers=self._collector._get_max_workers(),  # noqa: SLF001
        ).run(tasks)
        record_collection_results(self._collector.session, results)
        services: list[dict[str, Any]] = []
        for result in results:
            if result.status == "completed" and result.value is not None:
                services.extend(result.value.services)
                self._collector._extend_unique(  # noqa: SLF001
                    permission_errors,
                    result.value.permission_errors,
                )
                continue
            if result.error_code:
                self._collector._extend_unique(  # noqa: SLF001
                    permission_errors,
                    [f"describe_services:{result.error_code}"],
                )
        return services

    def _describe_ecs_service_collection(
        self,
        client: Any,  # noqa: ANN401
        cluster_arn: str,
        service_arns: list[str],
    ) -> EcsServiceDetailCollection:
        permission_errors: list[str] = []
        return EcsServiceDetailCollection(
            cluster_arn=cluster_arn,
            services=self._collector._describe_ecs_services(  # noqa: SLF001
                client,
                cluster_arn,
                service_arns,
                permission_errors,
            ),
            permission_errors=permission_errors,
        )

    def _sum_ecs_tasks_by_launch_type(
        self,
        services: list[dict[str, Any]],
        launch_type: str,
        count_key: str,
    ) -> int:
        return sum(self._collector._get_int(service.get(count_key)) for service in services if self._collector._get_ecs_launch_type(service) == launch_type)  # noqa: SLF001

    def _describe_ecs_task_definitions(
        self,
        client: Any,  # noqa: ANN401
        task_definition_arns: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        tasks = [
            AwsCollectionTask(
                name=(f"ManagedPlatformInventoryCollector:ecs-task-definition:{task_definition_arn}"),
                scanner_id=self._collector.audit_context.scanner_id,
                collector_id=self._collector.audit_context.collector,
                account_id=self._collector.account_id,
                region=self._collector._extract_region_from_arn(task_definition_arn),  # noqa: SLF001
                service="ecs",
                operation="DescribeTaskDefinition",
                payload={"task_definition_arn": task_definition_arn},
                collect=lambda task_definition_arn=task_definition_arn: self._collector._describe_ecs_task_definition(  # noqa: SLF001
                    client,
                    task_definition_arn,
                ),
            )
            for task_definition_arn in task_definition_arns
        ]
        results = AwsCollectionExecutor(
            max_workers=self._collector._get_max_workers(),  # noqa: SLF001
        ).run(tasks)
        record_collection_results(self._collector.session, results)
        return self._collector._build_ecs_task_definitions_from_results(  # noqa: SLF001
            results,
            permission_errors,
        )

    def _describe_ecs_task_definitions_if_enabled(
        self,
        client: Any,  # noqa: ANN401
        task_definition_arns: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        if self._collector.ecs_task_definition_detail_mode == "summary":
            return []
        return self._collector._describe_ecs_task_definitions(  # noqa: SLF001
            client,
            task_definition_arns,
            permission_errors,
        )

    def _describe_ecs_task_definition(
        self,
        client: Any,  # noqa: ANN401
        task_definition_arn: str,
    ) -> dict[str, Any] | None:
        response = client.describe_task_definition(
            taskDefinition=task_definition_arn,
            include=["TAGS"],
        )
        task_definition = response.get("taskDefinition")
        return task_definition if isinstance(task_definition, dict) else None

    def _build_ecs_task_definitions_from_results(
        self,
        results: list[AwsCollectionTaskResult[dict[str, Any] | None]],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        task_definitions: list[dict[str, Any]] = []
        for result in results:
            if result.status == "completed":
                if result.value is not None:
                    task_definitions.append(result.value)
                continue
            if result.error_code:
                self._collector._extend_unique(  # noqa: SLF001
                    permission_errors,
                    [f"describe_task_definition:{result.error_code}"],
                )
        return task_definitions

    def _extract_region_from_arn(self, arn: str) -> str | None:
        parts = arn.split(":")
        if len(parts) > 3 and parts[3]:  # noqa: PLR2004
            return parts[3]
        return None
