from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.ecs.region_record import EcsRegionRecord


class ManagedPlatformEcsCollectionMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_ecs_record(self, region: str) -> list[EcsRegionRecord]:
        permission_errors: list[str] = []
        client = self._collector._safe_client("ecs", region, permission_errors)  # noqa: SLF001
        if client is None:
            return [
                EcsRegionRecord(
                    account_id=self._collector.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]
        cluster_arns = self._collector._collect_ecs_cluster_arns(  # noqa: SLF001
            client,
            permission_errors,
        )
        clusters = self._collector._describe_ecs_clusters(  # noqa: SLF001
            client,
            cluster_arns,
            permission_errors,
        )
        service_arns_by_cluster = self._collector._collect_ecs_service_arns_by_cluster(  # noqa: SLF001
            client,
            cluster_arns,
            permission_errors,
        )
        services = self._collector._describe_ecs_services_by_cluster(  # noqa: SLF001
            client,
            service_arns_by_cluster,
            permission_errors,
        )
        task_definitions = self._collector._describe_ecs_task_definitions_if_enabled(  # noqa: SLF001
            client,
            self._collector._get_ecs_task_definition_arns(services),  # noqa: SLF001
            permission_errors,
        )
        launch_types = [self._collector._get_ecs_launch_type(service) for service in services if self._collector._get_ecs_launch_type(service)]  # noqa: SLF001
        capacity_providers = [provider for service in services for provider in self._collector._get_ecs_capacity_providers(service)]  # noqa: SLF001
        deployments = self._collector._get_ecs_deployments(services)  # noqa: SLF001
        recent_events = self._collector._get_ecs_recent_service_events(services)  # noqa: SLF001
        return [
            EcsRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                cluster_count=len(cluster_arns),
                active_cluster_count=sum(1 for cluster in clusters if str(cluster.get("status") or "").upper() == "ACTIVE"),
                service_count=len(services),
                active_service_count=sum(1 for service in services if str(service.get("status") or "").upper() == "ACTIVE"),
                fargate_service_count=sum(1 for launch_type in launch_types if launch_type == "FARGATE"),
                ec2_service_count=sum(1 for launch_type in launch_types if launch_type == "EC2"),
                external_service_count=sum(1 for launch_type in launch_types if launch_type == "EXTERNAL"),
                desired_task_count=sum(self._collector._get_int(service.get("desiredCount")) for service in services),  # noqa: SLF001
                running_task_count=sum(self._collector._get_int(service.get("runningCount")) for service in services),  # noqa: SLF001
                pending_task_count=sum(self._collector._get_int(service.get("pendingCount")) for service in services),  # noqa: SLF001
                fargate_desired_task_count=self._collector._sum_ecs_tasks_by_launch_type(  # noqa: SLF001
                    services,
                    "FARGATE",
                    "desiredCount",
                ),
                fargate_running_task_count=self._collector._sum_ecs_tasks_by_launch_type(  # noqa: SLF001
                    services,
                    "FARGATE",
                    "runningCount",
                ),
                ec2_desired_task_count=self._collector._sum_ecs_tasks_by_launch_type(  # noqa: SLF001
                    services,
                    "EC2",
                    "desiredCount",
                ),
                ec2_running_task_count=self._collector._sum_ecs_tasks_by_launch_type(  # noqa: SLF001
                    services,
                    "EC2",
                    "runningCount",
                ),
                service_with_desired_tasks_count=sum(1 for service in services if self._collector._get_int(service.get("desiredCount")) > 0),  # noqa: SLF001
                service_with_pending_tasks_count=sum(1 for service in services if self._collector._get_int(service.get("pendingCount")) > 0),  # noqa: SLF001
                service_without_running_tasks_count=sum(
                    1
                    for service in services
                    if self._collector._get_int(service.get("desiredCount")) > 0 and self._collector._get_int(service.get("runningCount")) <= 0  # noqa: SLF001
                ),
                service_with_multiple_deployments_count=sum(1 for service in services if len(self._collector._get_ecs_service_deployments(service)) > 1),  # noqa: SLF001
                deployment_count=len(deployments),
                in_progress_deployment_count=sum(1 for deployment in deployments if str(deployment.get("rolloutState") or "").upper() == "IN_PROGRESS"),
                failed_deployment_count=sum(1 for deployment in deployments if str(deployment.get("rolloutState") or "").upper() == "FAILED"),
                recent_service_event_count=len(recent_events),
                task_definition_detail_collected=(self._collector.ecs_task_definition_detail_mode == "full"),
                task_definition_count=len(task_definitions),
                task_definition_cpu_units_total=sum(self._collector._get_int(task_definition.get("cpu")) for task_definition in task_definitions),  # noqa: SLF001
                task_definition_memory_mb_total=sum(self._collector._get_int(task_definition.get("memory")) for task_definition in task_definitions),  # noqa: SLF001
                task_definition_with_explicit_cpu_count=sum(1 for task_definition in task_definitions if task_definition.get("cpu")),
                task_definition_with_explicit_memory_count=sum(1 for task_definition in task_definitions if task_definition.get("memory")),
                tagged_cluster_count=sum(1 for cluster in clusters if cluster.get("tags")),
                untagged_cluster_count=sum(1 for cluster in clusters if not cluster.get("tags")),
                tagged_service_count=sum(1 for service in services if service.get("tags")),
                untagged_service_count=sum(1 for service in services if not service.get("tags")),
                sample_cluster_names=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._get_ecs_name(cluster, "clusterName") for cluster in clusters],  # noqa: SLF001
                ),
                sample_service_names=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._get_ecs_name(service, "serviceName") for service in services],  # noqa: SLF001
                ),
                sample_services_without_running_tasks=self._collector._limit_samples(  # noqa: SLF001
                    [
                        self._collector._get_ecs_name(service, "serviceName")  # noqa: SLF001
                        for service in services
                        if self._collector._get_int(service.get("desiredCount")) > 0 and self._collector._get_int(service.get("runningCount")) <= 0  # noqa: SLF001
                    ],
                ),
                sample_services_with_pending_tasks=self._collector._limit_samples(  # noqa: SLF001
                    [
                        self._collector._get_ecs_name(service, "serviceName")  # noqa: SLF001
                        for service in services
                        if self._collector._get_int(service.get("pendingCount")) > 0  # noqa: SLF001
                    ],
                ),
                sample_untagged_cluster_names=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._get_ecs_name(cluster, "clusterName") for cluster in clusters if not cluster.get("tags")],  # noqa: SLF001
                ),
                sample_untagged_service_names=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._get_ecs_name(service, "serviceName") for service in services if not service.get("tags")],  # noqa: SLF001
                ),
                sample_launch_types=self._collector._limit_samples(launch_types),  # noqa: SLF001
                sample_capacity_providers=self._collector._limit_samples(  # noqa: SLF001
                    capacity_providers,
                ),
                sample_task_definition_families=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._get_ecs_task_definition_family(task_definition) for task_definition in task_definitions],  # noqa: SLF001
                ),
                sample_task_definition_sizes=self._collector._limit_samples(  # noqa: SLF001
                    [
                        self._collector._format_ecs_task_definition_size(  # noqa: SLF001
                            task_definition,
                        )
                        for task_definition in task_definitions
                    ],
                ),
                sample_recent_service_events=self._collector._limit_samples(  # noqa: SLF001
                    [self._collector._truncate_sample_text(event) for event in recent_events if event],  # noqa: SLF001
                ),
                permission_errors=permission_errors,
            ),
        ]
