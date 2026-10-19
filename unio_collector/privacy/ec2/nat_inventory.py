"""Closed NAT inventory fields and compatible factual metric observations."""

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
    "nat_state": {"pending", "failed", "available", "deleting", "deleted", "unknown"},
    "connectivity": {"public", "private"},
    "namespace": {"AWS/NATGateway"},
    "metric_name": {
        "BytesInFromSource",
        "BytesOutToDestination",
        "PeakBytesPerSecond",
        "PeakPacketsPerSecond",
        "ActiveConnectionCount",
        "ErrorPortAllocation",
        "PacketsDropCount",
    },
    "statistic": {"Sum", "Maximum"},
    "interpretation": {"observed", "insufficient_data", "low_utilization_signal", "above_low_utilization_threshold"},
    "status": {"complete", "partial", "unavailable"},
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "records[].nat_gateway_id": ("string", "resource_id", False),
    "records[].state": ("nat_state", "safe_metadata", False),
    "records[].subnet_id": ("string", "resource_id", True),
    "records[].vpc_id": ("string", "resource_id", True),
    "records[].connectivity_type": ("connectivity", "safe_metadata", True),
    "records[].create_time": ("timestamp", "timestamp", True),
    "records[].metric_summaries": ("array", "safe_metadata", False),
    "records[].metric_summaries[]": ("object", "safe_metadata", False),
    "records[].metric_summaries[].namespace": ("namespace", "safe_metadata", False),
    "records[].metric_summaries[].metric_name": ("metric_name", "safe_metadata", False),
    "records[].metric_summaries[].statistic": ("statistic", "safe_metadata", False),
    "records[].metric_summaries[].period": ("count", "safe_metadata", False),
    "records[].metric_summaries[].start_time": ("timestamp", "timestamp", False),
    "records[].metric_summaries[].end_time": ("timestamp", "timestamp", False),
    "records[].metric_summaries[].observed_min": ("money", "safe_metadata", True),
    "records[].metric_summaries[].observed_max": ("money", "safe_metadata", True),
    "records[].metric_summaries[].observed_average": ("money", "safe_metadata", True),
    "records[].metric_summaries[].threshold_used": ("money", "safe_metadata", True),
    "records[].metric_summaries[].interpretation": ("interpretation", "safe_metadata", False),
    "records[].metric_summaries[].limitation": ("string", "free_text", True),
    "records[].metric_summaries[].datapoints": ("array", "safe_metadata", False),
    "records[].metric_summaries[].datapoints[]": ("object", "safe_metadata", False),
    "records[].metric_summaries[].datapoints[].timestamp": ("timestamp", "timestamp", False),
    "records[].metric_summaries[].datapoints[].value": ("money", "safe_metadata", False),
    "records[].metric_summaries[].collection_evidence_version": ("version", "safe_metadata", False),
    "records[].metric_summaries[].collection_context": ("context", "safe_metadata", True),
    "records[].metric_summaries[].collection_status": ("status", "safe_metadata", True),
    "records[].metric_summaries[].collection_reason": ("reason", "safe_metadata", True),
    "records[].metric_summaries[].observed_average_parts": ("parts", "safe_metadata", True),
    "records[].metric_summaries[].observed_average_parts[]": ("parts_item", "safe_metadata", False),
    "records[].metric_summaries[].observed_average_parts[][]": ("digit", "safe_metadata", False),
}


class NatInventoryPrivacyContract(Ec2PrivacyContract):
    """Admit only exact NAT inventory identities and complete declared containers."""

    scanner_id: ClassVar[str] = "nat-gateway-inventory"
    fixture_type: ClassVar[str] = "NatGatewayFixtureEvidence"
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
            return type(value) is int and value == MetricCollectionContext.NAT_GATEWAY
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
        if not failures and suffix == "records[].metric_summaries[]" and isinstance(value, dict) and not LoadBalancerMetricValidator.validate(value):
            return [member + PREFIX[1:] + "." + suffix]
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole diagnostic strings while preserving their presence and count."""
        decision = super().resolve(path, profile)
        if decision is not None and path == PREFIX + ".records[].metric_summaries[].limitation":
            return replace(decision, treatment="tokenise", reason="Arbitrary diagnostic text is protected without erasing evidence of limitations.")
        return decision
