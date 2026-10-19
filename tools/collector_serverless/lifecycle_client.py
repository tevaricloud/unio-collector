"""Actual six-service SDK shapes for lifecycle evidence, without live providers."""

from __future__ import annotations

from typing import Any

from tools.collector_serverless.base import SyntheticServerlessClient, synthetic_arn


class SyntheticLifecycleClient(SyntheticServerlessClient):
    """Populate each actual service discriminator and conditional AMI attributes."""

    def describe_db_instances(self, **_kwargs: object) -> dict[str, Any]:
        """Retain optional RDS engine/version fields and resource identity."""
        row: dict[str, Any] = {
            "DBInstanceIdentifier": "synthetic-customer-db",
            "DBInstanceArn": synthetic_arn("rds", "db:synthetic-customer-db"),
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
        }
        if self.session.variant == "nullable":
            row.update(Engine=None, EngineVersion=None, DBInstanceArn=None)
        return self._response("describe_db_instances", "DBInstances", [row])

    def list_tags_for_resource(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise actual tag extraction and the supported tag-unavailable path."""
        self._fail("list_tags_for_resource")
        tags = [{"Key": "synthetic-customer-key", "Value": "synthetic-customer-value"}]
        if self.session.variant in {"environment_tags", "native"}:
            tags.extend([{"Key": "Environment", "Value": "production"}, {"Key": "Owner", "Value": "production"}])
        return {"TagList": tags}

    def describe_instances(self, **_kwargs: object) -> dict[str, Any]:
        """Populate actual instance-to-image discovery rather than a version DTO."""
        return self._response(
            "describe_instances",
            "Reservations",
            [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "ImageId": "ami-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "Tags": [{"Key": "Name", "Value": "synthetic-customer-node"}],
                        }
                    ]
                }
            ],
        )

    def describe_images(self, **_kwargs: object) -> dict[str, Any]:
        """Drive public image metadata and the actual unavailable-image branch."""
        return self._response(
            "describe_images",
            "Images",
            [{"ImageId": "ami-0123456789abcdef0", "Name": "synthetic-customer-image", "PlatformDetails": "Linux/UNIX", "CreationDate": "2024-01-01T00:00:00Z"}],
        )

    def describe_cache_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Populate cache engine/version evidence including declared nulls."""
        return self._response(
            "describe_cache_clusters",
            "CacheClusters",
            [
                {
                    "CacheClusterId": "synthetic-customer-cache",
                    "Engine": None if self.session.variant == "nullable" else "redis",
                    "EngineVersion": None if self.session.variant == "nullable" else "6.2",
                    "ARN": synthetic_arn("elasticache", "cluster:synthetic-customer-cache"),
                }
            ],
        )

    def list_domain_names(self, **_kwargs: object) -> dict[str, Any]:
        """Use the actual domain discovery and describe sequence."""
        return self._response("list_domain_names", "DomainNames", [{"DomainName": "synthetic-customer-domain"}])

    def describe_domains(self, **_kwargs: object) -> dict[str, Any]:
        """Retain the real engine/version source field and optional ARN."""
        return self._response(
            "describe_domains",
            "DomainStatusList",
            [{"DomainName": "synthetic-customer-domain", "EngineVersion": "OpenSearch_1.3", "ARN": synthetic_arn("es", "domain/synthetic-customer-domain")}],
        )

    def list_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Discover a real EKS name for the actual follow-up request."""
        return self._response("list_clusters", "clusters", ["synthetic-customer-eks"])

    def describe_cluster(self, **_kwargs: object) -> dict[str, Any]:
        """Populate actual Kubernetes version and dynamic customer tags."""
        self._fail("describe_cluster")
        return {
            "cluster": {
                "version": "1.29",
                "arn": synthetic_arn("eks", "cluster/synthetic-customer-eks"),
                "tags": {"synthetic-customer-key": "synthetic-customer-value"},
            }
        }
