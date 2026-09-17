from __future__ import annotations  # noqa: D100

from typing import Any


class ManagedPlatformEcsHelpersMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _get_ecs_launch_type(self, service: dict[str, Any]) -> str:
        launch_type = str(service.get("launchType") or "").upper()
        if launch_type:
            return launch_type
        capacity_providers = self._collector._get_ecs_capacity_providers(service)  # noqa: SLF001
        if any("FARGATE" in provider for provider in capacity_providers):
            return "FARGATE"
        if capacity_providers:
            return "EC2"
        return ""

    def _get_ecs_capacity_providers(self, service: dict[str, Any]) -> list[str]:
        strategy = service.get("capacityProviderStrategy")
        if not isinstance(strategy, list):
            return []
        providers: list[str] = []
        for item in strategy:
            if not isinstance(item, dict):
                continue
            provider = item.get("capacityProvider")
            if provider:
                providers.append(str(provider))
        return providers

    def _get_ecs_task_definition_arns(
        self,
        services: list[dict[str, Any]],
    ) -> list[str]:
        seen: set[str] = set()
        task_definition_arns: list[str] = []
        for service in services:
            task_definition = service.get("taskDefinition")
            if not task_definition:
                continue
            task_definition_arn = str(task_definition)
            if task_definition_arn in seen:
                continue
            seen.add(task_definition_arn)
            task_definition_arns.append(task_definition_arn)
        return task_definition_arns

    def _get_ecs_deployments(
        self,
        services: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        deployments: list[dict[str, Any]] = []
        for service in services:
            deployments.extend(self._collector._get_ecs_service_deployments(service))  # noqa: SLF001
        return deployments

    def _get_ecs_service_deployments(
        self,
        service: dict[str, Any],
    ) -> list[dict[str, Any]]:
        deployments = service.get("deployments")
        if not isinstance(deployments, list):
            return []
        return [item for item in deployments if isinstance(item, dict)]

    def _get_ecs_recent_service_events(
        self,
        services: list[dict[str, Any]],
    ) -> list[str]:
        messages: list[str] = []
        for service in services:
            service_name = self._collector._get_ecs_name(service, "serviceName")  # noqa: SLF001
            events = service.get("events")
            if not isinstance(events, list):
                continue
            for event in events[:2]:
                if not isinstance(event, dict) or not event.get("message"):
                    continue
                prefix = f"{service_name}: " if service_name else ""
                messages.append(f"{prefix}{event['message']}")
        return messages

    def _get_ecs_task_definition_family(
        self,
        task_definition: dict[str, Any],
    ) -> str:
        family = task_definition.get("family")
        if family:
            return str(family)
        arn = str(task_definition.get("taskDefinitionArn") or "")
        if not arn:
            return ""
        name = arn.rsplit("/", 1)[-1]
        return name.split(":", 1)[0]

    def _format_ecs_task_definition_size(
        self,
        task_definition: dict[str, Any],
    ) -> str:
        family = self._collector._get_ecs_task_definition_family(task_definition)  # noqa: SLF001
        cpu = self._collector._get_int(task_definition.get("cpu"))  # noqa: SLF001
        memory = self._collector._get_int(task_definition.get("memory"))  # noqa: SLF001
        label = family or "task definition"
        if cpu and memory:
            return f"{label}: {cpu} CPU units / {memory} MiB"
        if cpu:
            return f"{label}: {cpu} CPU units"
        if memory:
            return f"{label}: {memory} MiB"
        return label

    def _get_ecs_name(self, item: dict[str, Any], key: str) -> str:
        value = item.get(key)
        if value:
            return str(value)
        arn = str(item.get("clusterArn") or item.get("serviceArn") or "")
        return arn.rsplit("/", 1)[-1] if arn else ""
