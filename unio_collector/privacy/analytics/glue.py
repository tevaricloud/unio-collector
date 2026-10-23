"""Explicit Glue collection evidence, whole numeric rows and conditional nulls."""

from __future__ import annotations

from math import isfinite
from typing import Any, ClassVar, Self

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows
from unio_collector.privacy.analytics.fields import COMMON, GLUE_COUNTS, GLUE_NAMES, matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

NUMERIC_WIDTHS = {"records[].job_numeric_evidence": 2, "records[].run_numeric_evidence": 3}
NUMERIC_KEYS = {"field_count", "rows", "seen_count", "omitted_count", "read_complete"}


class GluePrivacyContract(ClosedProducerContract):
    """Validate finite typed numeric evidence before any profile-driven omission."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        **COMMON,
        **names_and_counts(GLUE_COUNTS, GLUE_NAMES),
        **fields("records[].total_dpu_seconds", "number"),
        **fields("records[].job_run_collection_limited", "boolean"),
        **fields("records[].collection_evidence_version records[].policy_input_source", "version"),
        **fields("records[].configured_run_duration", "integer", nullable=True),
        **fields("records[].configured_run_dpu", "number", nullable=True),
        **dict.fromkeys(NUMERIC_WIDTHS, ("object", "safe_metadata", True)),
        **{
            key + "." + name: spec
            for key in NUMERIC_WIDTHS
            for name, spec in {
                "field_count": ("width", "safe_metadata", False),
                "rows": ("array", "safe_metadata", False),
                "rows[]": ("array", "safe_metadata", False),
                "rows[][]": ("number", "safe_metadata", True),
                "seen_count": ("count", "summary_count", False),
                "omitted_count": ("count", "summary_count", False),
                "read_complete": ("boolean", "safe_metadata", False),
            }.items()
        },
    }

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind the actual legacy DTO, not a merely similar scanner name."""
        return cls() if matching_identity(record, "glue-job-crawler-cost-review", "analytics_ai.glue", "GlueJobCrawlerCostReviewEvidence") else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind == "integer":
            return type(value) is int
        if kind == "width":
            return type(value) is int and value in {2, 3}
        if kind == "number":
            return type(value) is int or (type(value) is float and isfinite(value))
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require complete bounded numeric row DTOs with their exact per-role width."""
        errors = super().unknown_paths(value, member, suffix)
        if suffix in NUMERIC_WIDTHS and isinstance(value, dict) and not errors:
            if set(value) != NUMERIC_KEYS or value["field_count"] != NUMERIC_WIDTHS[suffix]:
                return [member + self.prefix[1:] + "." + suffix]
            try:
                NumericEvidenceRows(
                    field_count=value["field_count"],
                    rows=tuple(tuple(row) for row in value["rows"]),
                    seen_count=value["seen_count"],
                    omitted_count=value["omitted_count"],
                    read_complete=value["read_complete"],
                )
            except (KeyError, TypeError, ValueError, OverflowError):
                errors.append(member + self.prefix[1:] + "." + suffix)
        return errors
