from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime, time
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.elasticache.region_record import ElastiCacheRegionRecord
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest

if TYPE_CHECKING:
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod


class ManagedPlatformElastiCacheMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_elasticache_record(
        self,
        region: str,
        scan_period: ScanPeriod | None,
    ) -> list[ElastiCacheRegionRecord]:
        permission_errors: list[str] = []
        client = self._collector._safe_client("elasticache", region, permission_errors)  # noqa: SLF001
        if client is None:
            return [
                ElastiCacheRegionRecord(
                    account_id=self._collector.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]
        clusters = self._collector._collect_elasticache_clusters(  # noqa: SLF001
            client,
            permission_errors,
        )
        replication_groups = self._collector._collect_elasticache_replication_groups(  # noqa: SLF001
            client,
            permission_errors,
        )
        metrics_by_cluster = self._collector._collect_elasticache_metrics(  # noqa: SLF001
            region,
            clusters,
            scan_period,
        )
        metric_rollup = self._collector._summarize_elasticache_metrics(  # noqa: SLF001
            metrics_by_cluster,
        )
        return [
            ElastiCacheRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                cache_cluster_count=len(clusters),
                replication_group_count=len(replication_groups),
                available_cluster_count=sum(1 for cluster in clusters if str(cluster.get("CacheClusterStatus") or "").lower() == "available"),
                total_node_count=sum(self._collector._get_int(cluster.get("NumCacheNodes")) for cluster in clusters),  # noqa: SLF001
                multi_az_replication_group_count=sum(1 for group in replication_groups if str(group.get("MultiAZ") or "").lower() == "enabled"),
                automatic_failover_enabled_count=sum(1 for group in replication_groups if str(group.get("AutomaticFailover") or "").lower() == "enabled"),
                cluster_mode_enabled_count=sum(1 for group in replication_groups if self._collector._has_elasticache_cluster_mode(group)),  # noqa: SLF001
                sample_cluster_ids=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("CacheClusterId")) for cluster in clusters if cluster.get("CacheClusterId")],
                ),
                sample_replication_group_ids=self._collector._limit_samples(  # noqa: SLF001
                    [str(group.get("ReplicationGroupId")) for group in replication_groups if group.get("ReplicationGroupId")],
                ),
                sample_engine_versions=self._collector._limit_samples(  # noqa: SLF001
                    [
                        engine_version
                        for cluster in clusters
                        if (
                            engine_version := (
                                self._collector._format_elasticache_engine_version(  # noqa: SLF001
                                    cluster,
                                )
                            )
                        )
                    ],
                ),
                metric_detail_collected=(self._collector.elasticache_metric_detail_mode == "full"),
                metric_cluster_count=metric_rollup["metric_cluster_count"],
                metric_observation_count=metric_rollup["metric_observation_count"],
                sample_metric_cluster_ids=metric_rollup["sample_metric_cluster_ids"],
                metric_cluster_ids=metric_rollup["metric_cluster_ids"],
                metrics=metric_rollup["metrics"],
                permission_errors=permission_errors,
            ),
        ]

    def _collect_elasticache_metrics(
        self,
        region: str,
        clusters: list[dict[str, Any]],
        scan_period: ScanPeriod | None,
    ) -> dict[str, list[MetricSummary]]:
        if scan_period is None:
            return {}
        if self._collector.elasticache_metric_detail_mode == "summary":
            return {}
        cluster_ids = [str(cluster.get("CacheClusterId") or "") for cluster in clusters if cluster.get("CacheClusterId")]
        if not cluster_ids:
            return {}
        metrics = CloudWatchMetricCollector(
            self._collector.session,
            region=region,
            audit_context=self._collector.audit_context,
        )
        requests: list[MetricRequest] = []
        owners: list[str] = []
        for cluster_id in cluster_ids:
            cluster_requests = self._collector._build_elasticache_metric_requests(  # noqa: SLF001
                cluster_id,
                scan_period,
            )
            requests.extend(cluster_requests)
            owners.extend([cluster_id] * len(cluster_requests))
        summaries = metrics.collect_metric_summaries(requests)
        by_cluster: dict[str, list[MetricSummary]] = {str(cluster.get("CacheClusterId") or ""): [] for cluster in clusters if cluster.get("CacheClusterId")}
        for cluster_id, summary in zip(owners, summaries, strict=True):
            by_cluster.setdefault(cluster_id, []).append(summary)
        return by_cluster

    def _build_elasticache_metric_requests(
        self,
        cluster_id: str,
        scan_period: ScanPeriod,
    ) -> list[MetricRequest]:
        start_time = datetime.combine(
            scan_period.current_start_date,
            time.min,
            tzinfo=UTC,
        )
        end_time = datetime.combine(
            scan_period.current_end_exclusive,
            time.min,
            tzinfo=UTC,
        )
        dimensions = [{"Name": "CacheClusterId", "Value": cluster_id}]
        metric_specs = (
            ("CPUUtilization", "Average"),
            ("EngineCPUUtilization", "Average"),
            ("DatabaseMemoryUsagePercentage", "Average"),
            ("CurrConnections", "Average"),
            ("Evictions", "Sum"),
            ("CacheHits", "Sum"),
            ("CacheMisses", "Sum"),
        )
        return [
            MetricRequest(
                namespace="AWS/ElastiCache",
                metric_name=metric_name,
                dimensions=dimensions,
                statistic=statistic,
                period=3600,
                start_time=start_time,
                end_time=end_time,
                collection_context=MetricCollectionContext.ELASTICACHE_CLUSTER,
            )
            for metric_name, statistic in metric_specs
        ]

    def _summarize_elasticache_metrics(
        self,
        metrics_by_cluster: dict[str, list[MetricSummary]],
    ) -> dict[str, Any]:
        observed_cluster_ids: list[str] = []
        metric_cluster_ids: list[str] = []
        all_metrics: list[MetricSummary] = []
        observation_count = 0

        for cluster_id, metrics in metrics_by_cluster.items():
            all_metrics.extend(metrics)
            metric_cluster_ids.extend([cluster_id] * len(metrics))
            observed_metrics = [metric for metric in metrics if metric.observed_average is not None]
            if observed_metrics:
                observed_cluster_ids.append(cluster_id)
                observation_count += len(observed_metrics)

        return {
            "metric_cluster_count": len(observed_cluster_ids),
            "metric_observation_count": observation_count,
            "sample_metric_cluster_ids": self._collector._limit_samples(  # noqa: SLF001
                observed_cluster_ids,
            ),
            "metric_cluster_ids": metric_cluster_ids,
            "metrics": all_metrics,
        }

    def _collect_elasticache_replication_groups(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "describe_replication_groups",
                result_key="ReplicationGroups",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_replication_groups",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "ReplicationGroups")  # noqa: SLF001

    def _format_elasticache_engine_version(
        self,
        cluster: dict[str, Any],
    ) -> str:
        engine = str(cluster.get("Engine") or "").strip()
        version = str(cluster.get("EngineVersion") or "").strip()
        if engine and version:
            return f"{engine} {version}"
        return engine or version
