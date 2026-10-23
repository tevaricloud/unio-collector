"""Actual ECS SDK response shapes for registered managed collection."""

from __future__ import annotations

from typing import Any, ClassVar

from tools.collector_managed.base import SyntheticManagedSession


class SyntheticEcsSession(SyntheticManagedSession):
    """Feed real discovery, descriptions, services and task-definition branches."""

    failing_operations: ClassVar[frozenset[str]] = frozenset({"describe_services"})

    def list_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Discover the actual source-owned synthetic cluster identity."""
        return self._response("list_clusters", "clusterArns", [f"arn:aws:ecs:{self.region}:123456789012:cluster/synthetic-customer-cluster"])

    def describe_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise actual active, tagged and untagged cluster controls."""
        return self._response(
            "describe_clusters",
            "clusters",
            [{"clusterName": "synthetic-customer-cluster", "status": "ACTIVE", "tags": [{"key": "Owner", "value": "synthetic-customer-owner"}]}],
        )

    def list_services(self, **_kwargs: object) -> dict[str, Any]:
        """Discovery uses real ARN extraction and per-cluster request composition."""
        return self._response(
            "list_services",
            "serviceArns",
            [
                f"arn:aws:ecs:{self.region}:123456789012:service/synthetic-customer-cluster/{name}"
                for name in ("synthetic-customer-service", "synthetic-customer-ec2-service")
            ],
        )

    def describe_services(self, **_kwargs: object) -> dict[str, Any]:
        """Populate deployments, task counts, launch/capacity metadata and free text."""
        services = [
            {
                "serviceName": "synthetic-customer-service",
                "status": "ACTIVE",
                "launchType": "FARGATE",
                "desiredCount": 2,
                "runningCount": 0,
                "pendingCount": 1,
                "capacityProviderStrategy": [{"capacityProvider": "FARGATE_SPOT"}],
                "taskDefinition": f"arn:aws:ecs:{self.region}:123456789012:task-definition/synthetic-customer-task:1",
                "deployments": [{"rolloutState": "IN_PROGRESS"}, {"rolloutState": "FAILED"}],
                "events": [{"message": "synthetic-customer-service-event"}],
                "tags": [],
            },
            {
                "serviceName": "synthetic-customer-ec2-service",
                "launchType": "EC2",
                "desiredCount": 1,
                "runningCount": 1,
                "tags": [{"key": "Owner", "value": "synthetic-customer-owner"}],
            },
        ]
        if self.variant == "nullable":
            services = [{"serviceName": "synthetic-customer-service", "desiredCount": None, "runningCount": None, "tags": None}]
        response = self._response("describe_services", "services", services)
        if self.variant == "partial":
            response["services"] = response["services"][:1]
            response["failures"] = [
                {
                    "arn": f"arn:aws:ecs:{self.region}:123456789012:service/synthetic-customer-cluster/synthetic-customer-ec2-service",
                    "reason": "ACCESS_DENIED",
                    "detail": "synthetic partial metadata",
                }
            ]
        return response

    def describe_task_definition(self, **_kwargs: object) -> dict[str, Any]:
        """Run actual task sizing extraction; summary mode must skip this request."""
        self._fail("describe_task_definition")
        return {"taskDefinition": {"family": "synthetic-customer-task", "cpu": "512", "memory": "1024", "containerDefinitions": [{"cpu": 128, "memory": 256}]}}
