"""Exact serverless MetricSummary fields and independently checked role pairs."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.ec2.metric import LoadBalancerMetricValidator
from unio_collector.privacy.s3.fields import fields

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

METRIC = "records[].metric_summaries[]"
METRIC_FIELDS = {
    **fields("records[].metric_summaries", "array"),
    **fields(METRIC, "object"),
    **{METRIC + "." + key: ("metric_" + key, "safe_metadata", False) for key in ("namespace", "metric_name", "statistic", "interpretation")},
    **fields(METRIC + ".period", "period"),
    **fields(" ".join(METRIC + "." + key for key in ("start_time", "end_time", "datapoints[].timestamp")), "timestamp", "timestamp"),
    **fields(" ".join(METRIC + "." + key for key in ("observed_min", "observed_max", "observed_average", "threshold_used")), "money", nullable=True),
    **fields(METRIC + ".limitation", "string", "free_text", nullable=True),
    **fields(METRIC + ".datapoints", "array"),
    **fields(METRIC + ".datapoints[]", "object"),
    **fields(METRIC + ".datapoints[].value", "money"),
    **fields(METRIC + ".collection_evidence_version", "version"),
    **fields(METRIC + ".collection_context", "none", nullable=True),
    **fields(METRIC + ".collection_status", "metric_status", nullable=True),
    **fields(METRIC + ".collection_reason", "reason", nullable=True),
    **fields(METRIC + ".observed_average_parts", "parts", nullable=True),
    **fields(METRIC + ".observed_average_parts[]", "parts_item"),
    **fields(METRIC + ".observed_average_parts[][]", "digit"),
}
LEGACY_REQUIRED = frozenset(
    {
        "namespace",
        "metric_name",
        "statistic",
        "period",
        "start_time",
        "end_time",
        "observed_min",
        "observed_max",
        "observed_average",
        "threshold_used",
        "interpretation",
    }
)
VOCABULARIES = {
    "metric_interpretation": {"observed", "insufficient_data", "low_utilization_signal", "above_low_utilization_threshold"},
    "metric_status": {"complete", "partial", "unavailable"},
}


class ServerlessMetricContract(ClosedProducerContract):
    """Admit actual null-context metrics with exact per-consumer namespace/name/statistic roles."""

    roles: ClassVar[frozenset[tuple[str, str, str]]] = frozenset()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind in {"metric_namespace", "metric_metric_name", "metric_statistic"}:
            index = {"metric_namespace": 0, "metric_metric_name": 1, "metric_statistic": 2}[kind]
            return isinstance(value, str) and value in {role[index] for role in cls.roles}
        checked = cls._primitive(value, kind)
        return checked if checked is not None else super()._valid(value, kind, nullable=nullable)

    @staticmethod
    def _primitive(value: object, kind: str) -> bool | None:
        """Validate bounded numeric, temporal and decimal tuple roles."""
        if kind in {"period", "version", "reason", "digit"}:
            if type(value) is not int:
                return False
            return {"period": value > 0, "version": value in {0, 1}, "reason": value in set(MetricReadReason), "digit": 0 <= value <= 9}[kind]  # noqa: PLR2004
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
        if kind == "none":
            return False
        return None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require complete metric keys, aggregate consistency and the declared role triple."""
        failures = super().unknown_paths(value, member, suffix)
        if not failures and suffix == METRIC and isinstance(value, dict):
            expected = {
                key[len(METRIC) + 1 :]
                for key in METRIC_FIELDS
                if key.startswith(METRIC + ".") and "." not in key[len(METRIC) + 1 :] and "[" not in key[len(METRIC) + 1 :]
            }
            if (
                not (expected if value.get("collection_evidence_version", 0) == 1 else LEGACY_REQUIRED).issubset(value)
                or not set(value).issubset(expected)
                or (value.get("namespace"), value.get("metric_name"), value.get("statistic")) not in self.roles
                or not LoadBalancerMetricValidator.validate(value)
            ):
                failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect entire arbitrary diagnostic prose, retaining actual metric magnitudes."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Normalize only exact finite metric roles; parent aggregate guard remains required."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0].startswith("metric_") and self._valid(value, spec[0], nullable=spec[2])
