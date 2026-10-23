"""Closed actual ElastiCache metadata and factual metric privacy contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.privacy.analytics.fields import matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.ec2.metric import LoadBalancerMetricValidator
from unio_collector.privacy.platform.fields import COMMON
from unio_collector.privacy.s3.fields import fields

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

COUNTS = (
    "cache_cluster_count replication_group_count available_cluster_count total_node_count multi_az_replication_group_count "
    "automatic_failover_enabled_count cluster_mode_enabled_count metric_cluster_count metric_observation_count "
    "low_activity_cluster_count low_cpu_cluster_count low_connection_cluster_count eviction_signal_cluster_count high_memory_pressure_cluster_count"
)
NAMES = (
    "sample_cluster_ids sample_replication_group_ids sample_engine_versions sample_metric_cluster_ids metric_cluster_ids "
    "sample_low_activity_cluster_ids sample_capacity_pressure_cluster_ids"
)
VOCABULARIES = {
    "cache_namespace": {"AWS/ElastiCache"},
    "cache_metric_name": {
        "CPUUtilization",
        "EngineCPUUtilization",
        "DatabaseMemoryUsagePercentage",
        "CurrConnections",
        "Evictions",
        "CacheHits",
        "CacheMisses",
    },
    "cache_statistic": {"Average", "Sum"},
    "cache_interpretation": {"observed", "insufficient_data", "low_utilization_signal", "above_low_utilization_threshold"},
    "cache_status": {"complete", "partial", "unavailable"},
}
METRIC = "records[].metrics[]"


class ElastiCachePrivacyContract(ClosedProducerContract):
    """Admit exact typed metric fields and retain neutral completeness consistency."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        **COMMON,
        **names_and_counts(COUNTS, NAMES),
        **fields("records[].metric_detail_collected", "boolean"),
        **fields("records[].metrics", "array"),
        **fields(METRIC, "object"),
        **{METRIC + "." + key: ("cache_" + key, "safe_metadata", False) for key in ("namespace", "metric_name", "statistic", "interpretation")},
        **fields(METRIC + ".period", "count"),
        **fields(METRIC + ".start_time " + METRIC + ".end_time " + METRIC + ".datapoints[].timestamp", "timestamp", "timestamp"),
        **fields(" ".join(METRIC + "." + key for key in ("observed_min", "observed_max", "observed_average", "threshold_used")), "money", nullable=True),
        **fields(METRIC + ".limitation", "string", "free_text", nullable=True),
        **fields(METRIC + ".datapoints", "array"),
        **fields(METRIC + ".datapoints[]", "object"),
        **fields(METRIC + ".datapoints[].value", "money"),
        **fields(METRIC + ".collection_evidence_version", "version"),
        **fields(METRIC + ".collection_context", "context", nullable=True),
        **fields(METRIC + ".collection_status", "cache_status", nullable=True),
        **fields(METRIC + ".collection_reason", "reason", nullable=True),
        **fields(METRIC + ".observed_average_parts", "parts", nullable=True),
        **fields(METRIC + ".observed_average_parts[]", "parts_item"),
        **fields(METRIC + ".observed_average_parts[][]", "digit"),
    }

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind only the actual legacy ElastiCache AWS evidence identity."""
        return cls() if matching_identity(record, "elasticache-cost-review", "platform.elasticache", "ElastiCacheCostReviewEvidence") else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        checked = cls._metric_value(value, kind)
        if checked is not None:
            return checked
        return super()._valid(value, kind, nullable=nullable)

    @staticmethod
    def _metric_value(value: object, kind: str) -> bool | None:
        """Validate the finite metric-specific scalar roles separately."""
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "context":
            return type(value) is int and value == MetricCollectionContext.ELASTICACHE_CLUSTER
        if kind == "reason":
            return type(value) is int and value in set(MetricReadReason)
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except (ValueError, OverflowError):
                return False
            return True
        if kind == "parts":
            return LoadBalancerMetricValidator.valid_parts(value)
        if kind == "parts_item":
            return type(value) is int or isinstance(value, list)
        if kind == "digit":
            return type(value) is int and 0 <= value <= 9  # noqa: PLR2004
        return None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Apply exact aggregate completeness checks after closed-field admission."""
        failures = super().unknown_paths(value, member, suffix)
        if not failures and suffix == METRIC and isinstance(value, dict) and not LoadBalancerMetricValidator.validate(value):
            return [member + PREFIX[1:] + "." + suffix]
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole arbitrary metric limitations while retaining their presence."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and path == PREFIX + "." + METRIC + ".limitation" else decision
