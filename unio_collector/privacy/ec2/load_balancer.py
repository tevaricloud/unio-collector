"""Closed load-balancer inventory and factual metric privacy contract."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract
from unio_collector.privacy.ec2.metric import LoadBalancerMetricValidator

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

VOCABULARIES = {
    "lb_type": {"application", "network", "gateway", "unknown"},
    "lb_state": {"active", "provisioning", "active_impaired", "failed", "unknown"},
    "health_mode": {"full", "summary"},
    "health_reason": {"skipped_by_target_health_detail_mode", "unavailable_evidence"},
    "tag_reason": {"skipped_by_collect_tags", "unavailable_evidence"},
    "namespace": {"AWS/ApplicationELB", "AWS/NetworkELB"},
    "metric_name": {"RequestCount", "ProcessedBytes", "HealthyHostCount", "UnHealthyHostCount"},
    "statistic": {"Sum", "Average"},
    "interpretation": {"observed", "insufficient_data", "low_utilization_signal", "above_low_utilization_threshold"},
    "status": {"complete", "partial", "unavailable"},
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "metadata.target_health_detail_mode": ("health_mode", "safe_metadata", False),
    "metadata.collect_tags": ("boolean", "safe_metadata", False),
    "records[].load_balancer_arn": ("string", "arn", False),
    "records[].load_balancer_name": ("string", "resource_name", False),
    "records[].load_balancer_type": ("lb_type", "safe_metadata", False),
    "records[].state": ("lb_state", "safe_metadata", False),
    "records[].target_group_count": ("count", "safe_metadata", False),
    "records[].registered_target_count": ("count", "safe_metadata", False),
    "records[].healthy_target_count": ("count", "safe_metadata", False),
    "records[].target_health_detail_mode": ("health_mode", "safe_metadata", False),
    "records[].target_health_metadata_collected": ("boolean", "safe_metadata", False),
    "records[].target_health_skip_reason": ("health_reason", "safe_metadata", True),
    "records[].tags_collected": ("boolean", "safe_metadata", False),
    "records[].tag_skip_reason": ("tag_reason", "safe_metadata", True),
    "records[].collection_errors": ("array", "safe_metadata", False),
    "records[].collection_errors[]": ("string", "free_text", False),
    "records[].metrics": ("array", "safe_metadata", False),
    "records[].metrics[]": ("object", "safe_metadata", False),
    "records[].metrics[].namespace": ("namespace", "safe_metadata", False),
    "records[].metrics[].metric_name": ("metric_name", "safe_metadata", False),
    "records[].metrics[].statistic": ("statistic", "safe_metadata", False),
    "records[].metrics[].period": ("count", "safe_metadata", False),
    "records[].metrics[].start_time": ("timestamp", "timestamp", False),
    "records[].metrics[].end_time": ("timestamp", "timestamp", False),
    "records[].metrics[].observed_min": ("money", "safe_metadata", True),
    "records[].metrics[].observed_max": ("money", "safe_metadata", True),
    "records[].metrics[].observed_average": ("money", "safe_metadata", True),
    "records[].metrics[].threshold_used": ("money", "safe_metadata", True),
    "records[].metrics[].interpretation": ("interpretation", "safe_metadata", False),
    "records[].metrics[].limitation": ("string", "free_text", True),
    "records[].metrics[].datapoints": ("array", "safe_metadata", False),
    "records[].metrics[].datapoints[]": ("object", "safe_metadata", False),
    "records[].metrics[].datapoints[].timestamp": ("timestamp", "timestamp", False),
    "records[].metrics[].datapoints[].value": ("money", "safe_metadata", False),
    "records[].metrics[].collection_evidence_version": ("version", "safe_metadata", False),
    "records[].metrics[].collection_context": ("context", "safe_metadata", True),
    "records[].metrics[].collection_status": ("status", "safe_metadata", True),
    "records[].metrics[].collection_reason": ("reason", "safe_metadata", True),
    "records[].metrics[].observed_average_parts": ("parts", "safe_metadata", True),
    "records[].metrics[].observed_average_parts[]": ("parts_item", "safe_metadata", False),
    "records[].metrics[].observed_average_parts[][]": ("digit", "safe_metadata", False),
}


class LoadBalancerPrivacyContract(Ec2PrivacyContract):
    """Retain numeric and limitation semantics under exact scanner identity."""

    scanner_id: ClassVar[str] = "load-balancer-idle-review"
    fixture_type: ClassVar[str] = "LoadBalancerFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate finite metadata and the exact Decimal representation."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "context":
            return type(value) is int and value == MetricCollectionContext.LOAD_BALANCER
        if kind == "reason":
            return type(value) is int and value in set(MetricReadReason)
        if kind == "parts":
            return LoadBalancerMetricValidator.valid_parts(value)
        if kind == "parts_item":
            return type(value) is int or isinstance(value, list)
        if kind == "digit":
            return type(value) is int and 0 <= value <= 9  # noqa: PLR2004
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Check aggregate consistency only after every nested field is admitted."""
        failures = super().unknown_paths(value, member, suffix)
        if not failures and suffix == "records[].metrics[]" and isinstance(value, dict) and not LoadBalancerMetricValidator.validate(value):
            return [member + PREFIX[1:] + "." + suffix]
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole diagnostic strings while preserving their presence and count."""
        decision = super().resolve(path, profile)
        if decision is not None and path in {PREFIX + ".records[].collection_errors[]", PREFIX + ".records[].metrics[].limitation"}:
            return replace(decision, treatment="tokenise", reason="Arbitrary diagnostic text is protected without erasing evidence of limitations.")
        return decision
