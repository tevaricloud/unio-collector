"""Actual ElastiCache metadata and batched CloudWatch response fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from tools.collector_managed.base import SyntheticManagedSession


class SyntheticCacheSession(SyntheticManagedSession):
    """Exercise actual metric collection, optional records and summary-only mode."""

    failing_operations: ClassVar[frozenset[str]] = frozenset({"get_metric_data"})

    def describe_cache_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Populate engine, identity, availability and node counts."""
        clusters = [
            {"CacheClusterId": "synthetic-customer-cache", "CacheClusterStatus": "available", "NumCacheNodes": 2, "Engine": "redis", "EngineVersion": "7.1"}
        ]
        if self.variant == "nullable":
            clusters = [{"CacheClusterId": "synthetic-customer-cache", "NumCacheNodes": None, "Engine": None, "EngineVersion": None}]
        return self._response("describe_cache_clusters", "CacheClusters", clusters)

    def describe_replication_groups(self, **_kwargs: object) -> dict[str, Any]:
        """Drive actual AZ, failover and cluster-mode counts and nullable branches."""
        return self._response(
            "describe_replication_groups",
            "ReplicationGroups",
            [{"ReplicationGroupId": "synthetic-customer-replica", "MultiAZ": "enabled", "AutomaticFailover": "enabled", "ClusterEnabled": True}],
        )

    def get_metric_data(self, **kwargs: object) -> dict[str, Any]:
        """Return actual query-ID correlations, timestamps and completeness statuses."""
        self._fail("get_metric_data")
        status = "PartialData" if self.variant == "partial" else "Complete"
        queries = kwargs["MetricDataQueries"]
        if not isinstance(queries, list):
            message = "Synthetic metric queries must be a list."
            raise TypeError(message)
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "Values": [] if self.variant == "no_data" else [1.25, 3.5],
                    "Timestamps": [] if self.variant == "no_data" else [datetime(2026, 9, 2, tzinfo=UTC), datetime(2026, 9, 3, tzinfo=UTC)],
                    "StatusCode": status,
                }
                for query in queries
            ]
        }
