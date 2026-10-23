"""Closed actual-producer privacy contract for athena-query-efficiency-review."""

from __future__ import annotations

from math import isfinite
from typing import Any, ClassVar, Self

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

ATHENA_NUMERIC_WIDTH = 3

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    "records[].workgroup_count": ("count", "safe_metadata", False),
    "records[].unbounded_workgroup_count": ("count", "safe_metadata", False),
    "records[].enforced_workgroup_count": ("count", "safe_metadata", False),
    "records[].metrics_enabled_workgroup_count": ("count", "safe_metadata", False),
    "records[].requester_pays_workgroup_count": ("count", "safe_metadata", False),
    "records[].data_catalog_count": ("count", "safe_metadata", False),
    "records[].query_execution_workgroups_checked": ("count", "safe_metadata", False),
    "records[].query_execution_count": ("count", "safe_metadata", False),
    "records[].failed_query_execution_count": ("count", "safe_metadata", False),
    "records[].long_running_query_count": ("count", "safe_metadata", False),
    "records[].high_bytes_scanned_query_count": ("count", "safe_metadata", False),
    "records[].total_bytes_scanned": ("count", "safe_metadata", False),
    "records[].total_engine_execution_ms": ("count", "safe_metadata", False),
    "records[].regional_cost_record_count": ("count", "safe_metadata", False),
    "records[].sample_workgroup_names": ("array", "resource_name", False),
    "records[].sample_workgroup_names[]": ("string", "resource_name", False),
    "records[].sample_data_catalog_names": ("array", "resource_name", False),
    "records[].sample_data_catalog_names[]": ("string", "resource_name", False),
    "records[].service_current_cost": ("money", "cost", True),
    "records[].service_previous_cost": ("money", "cost", True),
    "records[].regional_current_cost": ("money", "cost", True),
    "records[].service_cost_currency": ("string", "cost", True),
    "records[].regional_cost_currency": ("string", "cost", True),
    "records[].permission_errors": ("array", "removed_diagnostic", False),
    "records[].permission_errors[]": ("string", "removed_diagnostic", False),
    "records[].query_execution_collection_limited": ("boolean", "safe_metadata", False),
    "records[].collection_evidence_version": ("version", "safe_metadata", False),
    "records[].policy_input_source": ("version", "safe_metadata", False),
    "records[].configured_query_duration": ("integer", "safe_metadata", True),
    "records[].configured_query_bytes": ("integer", "safe_metadata", True),
    "records[].query_numeric_evidence": ("object", "safe_metadata", True),
    "records[].query_numeric_evidence.field_count": ("width", "safe_metadata", False),
    "records[].query_numeric_evidence.rows": ("array", "safe_metadata", False),
    "records[].query_numeric_evidence.rows[]": ("array", "safe_metadata", False),
    "records[].query_numeric_evidence.rows[][]": ("number", "safe_metadata", True),
    "records[].query_numeric_evidence.seen_count": ("count", "safe_metadata", False),
    "records[].query_numeric_evidence.omitted_count": ("count", "safe_metadata", False),
    "records[].query_numeric_evidence.read_complete": ("boolean", "safe_metadata", False),
    "records[].top_usage_type_costs": ("array", "cost", False),
    "records[].top_usage_type_costs[]": ("object", "cost", False),
    "records[].top_usage_type_costs[].usage_type": ("string", "free_text", False),
    "records[].top_usage_type_costs[].current_cost": ("money", "cost", False),
    "records[].top_usage_type_costs[].currency": ("string", "cost", False),
    "records[].top_usage_type_costs[].record_count": ("count", "safe_metadata", False),
}


class AthenaPrivacyContract(ClosedProducerContract):
    """Scope exact typed fields to the matching legacy AWS producer."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject conflicting identities before interpreting producer fields."""
        if record.get("scanner_id") != "athena-query-efficiency-review":
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {
                (f"{namespace}.scanners.analytics_ai.athena.evidence", "AthenaQueryEfficiencyReviewEvidence")
                for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            }
        ):
            message = "Inventory privacy contract requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate finite metadata before profile-driven omission."""
        if value is None:
            return nullable
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "integer":
            return type(value) is int
        if kind == "width":
            return type(value) is int and value == ATHENA_NUMERIC_WIDTH
        if kind == "number":
            return type(value) is int or (isinstance(value, float) and isfinite(value))
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Preserve actual numeric row bounds, completeness and shape invariants."""
        errors = super().unknown_paths(value, member, suffix)
        if not errors and suffix == "records[].query_numeric_evidence" and isinstance(value, dict):
            try:
                NumericEvidenceRows(
                    field_count=value["field_count"],
                    rows=tuple(tuple(row) for row in value["rows"]),
                    seen_count=value["seen_count"],
                    omitted_count=value["omitted_count"],
                    read_complete=value["read_complete"],
                )
            except (KeyError, TypeError, ValueError, OverflowError):
                return [member + ".scanner_evidence[].payload." + suffix]
        return errors
