"""Closed privacy contract for current compact CUR billing observations."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "summary": ("empty_object", "safe_metadata", False),
    "findings": ("empty_array", "safe_metadata", False),
    "collection_evidence_version": ("version", "safe_metadata", False),
    "billing_facts": ("object", "safe_metadata", False),
    "billing_facts.source_files": ("array", "safe_metadata", False),
    "billing_facts.source_files[]": ("string", "resource_name", False),
    **{f"billing_facts.{key}": ("count", "safe_metadata", False) for key in ("rows_read", "rows_matched", "rows_skipped")},
    **{f"billing_facts.{key}": ("money", "cost", False) for key in ("total_cost", "unassigned_cost", "assigned_cost", "tag_assignment_percentage")},
    "billing_facts.currency": ("string", "cost", False),
    "billing_facts.paths_supplied": ("boolean", "safe_metadata", False),
    "billing_facts.collection_status": ("status", "safe_metadata", False),
    "billing_facts.collection_issues": ("array", "safe_metadata", False),
    "billing_facts.collection_issues[]": ("object", "safe_metadata", False),
    "billing_facts.collection_issues[].error_code": ("issue", "safe_metadata", False),
    "billing_facts.aggregate_counts": ("object", "safe_metadata", False),
    **{f"billing_facts.aggregate_counts.{key}": ("count", "safe_metadata", False) for key in ("services", "regions", "usage_types", "resources", "tag_groups")},
    "billing_facts.limitations": ("array", "safe_metadata", False),
    "billing_facts.limitations[]": ("string", "free_text", False),
    **{f"billing_facts.{key}": ("array", "safe_metadata", False) for key in ("top_services", "top_regions", "top_usage_types", "top_resources", "tag_groups")},
    **{
        f"billing_facts.{key}[]": ("object", "safe_metadata", False)
        for key in ("top_services", "top_regions", "top_usage_types", "top_resources", "tag_groups")
    },
    **{f"billing_facts.{key}[].cost": ("money", "cost", False) for key in ("top_services", "top_regions", "top_usage_types", "top_resources")},
    "billing_facts.top_services[].service": ("string", "resource_name", False),
    "billing_facts.top_regions[].region": ("string", "region", False),
    "billing_facts.top_usage_types[].usage_type": ("string", "resource_name", True),
    "billing_facts.top_resources[].resource_id": ("string", "resource_id", False),
    "billing_facts.top_resources[].service": ("string", "resource_name", False),
    "billing_facts.top_resources[].region": ("string", "region", False),
    "billing_facts.top_resources[].account_id": ("string", "aws_account_id", True),
    "billing_facts.top_resources[].usage_type": ("string", "resource_name", True),
    "billing_facts.tag_groups[].group_key": ("string", "resource_name", False),
    "billing_facts.tag_groups[].group_value": ("string", "resource_name", False),
    "billing_facts.tag_groups[].estimated_cost": ("money", "cost", False),
}


class CurPrivacyContract(ClosedProducerContract):
    """Keep financial values distinct from counts and arbitrary customer text."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Admit only the exact current AWS collector DTO without decoder imports."""
        if record.get("scanner_id") != "cur-data-export-attribution":
            return None
        identities = {(f"{namespace}.scanners.cur_data_export.evidence", "CurDataExportEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
        ):
            message = "CUR privacy requires its registered AWS evidence identity."
            raise ValueError(message)

        payload = record.get("payload")
        version = payload.get("collection_evidence_version", 0) if isinstance(payload, dict) else None
        if type(version) is not int or version not in {0, 1}:
            message = "CUR privacy requires a supported integer collection version."
            raise ValueError(message)
        return None if version == 0 else cls()

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Every current projection object has a complete emitted key set."""
        failures = super().unknown_paths(value, member, suffix)
        if isinstance(value, dict) and suffix in self.fields and self.fields[suffix][0] == "object":
            stem = suffix + "." if suffix else ""
            required = {
                path[len(stem) :]
                for path in self.fields
                if path.startswith(stem) and path != suffix and "." not in path[len(stem) :] and "[" not in path[len(stem) :]
            }
            failures.extend(member + PREFIX[1:] + "." + stem + key for key in sorted(required - value.keys()))
        return failures

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect complete diagnostic bodies that may embed arbitrary source paths."""
        decision = super().resolve_string(path, value, profile)
        if decision is not None and path == self.prefix + ".billing_facts.limitations[]":
            return replace(decision, treatment="tokenise")
        return decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Recognize only validated finite status/issue roles, never customer positions."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in {"status", "issue"} and self._valid(value, spec[0], nullable=False)

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "version":
            return type(value) is int and value == 1
        if kind == "status":
            return isinstance(value, str) and value in {"complete", "partial", "unavailable"}
        if kind == "issue":
            return isinstance(value, str) and value in {"source_resolution_incomplete", "unreadable_billing_rows"}
        if kind == "empty_object":
            return isinstance(value, dict) and not value
        if kind == "empty_array":
            return isinstance(value, list) and not value
        return super()._valid(value, kind, nullable=nullable)
