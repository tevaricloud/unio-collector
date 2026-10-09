"""Closed actual CloudWatch Logs activity evidence privacy contract."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.ec2.base import Ec2PrivacyContract
from unio_collector.privacy.ec2.metric import LoadBalancerMetricValidator
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

SCANNERS = frozenset({"cloudwatch-idle-log-review", "cloudwatch-log-cost-and-relevance-review"})
VOCABULARIES = {
    "namespace": {"AWS/Logs"},
    "metric_name": {"IncomingBytes", "IncomingLogEvents"},
    "statistic": {"Sum"},
    "interpretation": {"observed", "insufficient_data", "low_utilization_signal", "above_low_utilization_threshold"},
    "status": {"complete", "partial", "unavailable"},
    "log_status": {"collected", "skipped_by_metric_detail_mode"},
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "idle_days": ("integer", "safe_metadata", False),
    "records[].log_group_name": ("string", "resource_name", False),
    "records[].region": ("string", "region", False),
    "records[].stored_bytes": ("count", "safe_metadata", True),
    "records[].retention_in_days": ("count", "safe_metadata", True),
    "records[].creation_time": ("timestamp", "timestamp", True),
    "records[].tags": ("tag_map", "tag_value", False),
    "records[].metric_collection_status": ("log_status", "safe_metadata", False),
    "records[].metric_collection_reason": ("string", "free_text", True),
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


class LogActivityPrivacyContract(Ec2PrivacyContract):
    """Bind two actual activity wrappers to explicit fields and metric consistency."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Admit only registered current or historical AWS activity identities."""
        if record.get("scanner_id") not in SCANNERS:
            return None
        schema = admit_evidence_schema(record)
        identities = {
            (f"{namespace}.scanners.{module}", kind)
            for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            for module, kind in (
                ("cloudwatch.log_activity.evidence", "CloudWatchLogActivityEvidence"),
                ("fixture_parity.synthetic_types", "CloudWatchLogActivityFixtureEvidence"),
            )
        }
        if schema is not None or record.get("provider_id", "aws") != "aws" or (record.get("evidence_module"), record.get("evidence_type")) not in identities:
            message = "CloudWatch activity privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate finite log metadata and the factual MetricSummary representation."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "integer":
            return type(value) is int
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "context":
            return type(value) is int and value == MetricCollectionContext.LOG_GROUP
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
        """Reuse the factual DTO validator only after this producer's closed preflight."""
        failures = super().unknown_paths(value, member, suffix)
        if not failures and suffix == "records[].metrics[]" and isinstance(value, dict) and not LoadBalancerMetricValidator.validate(value):
            return [member + PREFIX[1:] + "." + suffix]
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Tokenise whole diagnostics without erasing missing-evidence signals."""
        decision = super().resolve(path, profile)
        if decision is not None and path in {PREFIX + ".records[].metric_collection_reason", PREFIX + ".records[].metrics[].limitation"}:
            return replace(decision, treatment="tokenise", reason="Diagnostic presence is preserved while arbitrary text is protected.")
        return decision
