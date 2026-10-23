"""Closed actual CloudFront execution and configured invalidation-detail notes."""

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.edge.vocabulary import PRESERVED
from unio_collector.privacy.s3.fields import fields

SCANNER = "cloudfront-origin-cost-review"
LITERALS = {
    "scanner_id": {SCANNER},
    "note_type": {"execution_detail", "configuration_limit"},
    "scope_area": {"cloudfront_distribution_metadata", "cloudfront_invalidations"},
    "result_scope": {"current_scan"},
    "configured_value": {"full", "summary"},
    "config_key": {SCANNER + ".invalidation_detail_mode"},
    "metric_collection_status": PRESERVED["records[].metric_collection_status"],
}


class EdgeNoteContract(AuditNoteContract):
    """Protect arbitrary note text and reject unknown descendants before strict omission."""

    fields: ClassVar = {
        "": ("object", "safe_metadata", False),
        **fields(" ".join(LITERALS), "string"),
        **fields("summary impact metric_collection_reason", "string", "free_text"),
        **fields("regions_attempted", "array"),
        **fields("regions_attempted[]", "string", "region"),
        **fields("distribution_count enabled_distribution_count origin_count cache_behavior_count metric_distribution_count metric_datapoint_count", "count"),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Recognize the actual note's exact scanner or configured option identity."""
        return cls(SCANNER) if value.get("scanner_id") == SCANNER or value.get("config_key") == SCANNER + ".invalidation_detail_mode" else None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Enforce finite and mutually coherent note discriminators as well as field types."""
        failures = super(AuditNoteContract, self).unknown_paths(value, member, suffix)
        if suffix in LITERALS and (not isinstance(value, str) or value not in LITERALS[suffix]):
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "" and isinstance(value, dict):
            configured = value.get("note_type") == "configuration_limit"
            required = {"note_type", "scope_area", "summary", "result_scope", "impact"}
            required |= {"config_key", "configured_value"} if configured else {"scanner_id", "regions_attempted", "metric_collection_status"}
            scope = "cloudfront_invalidations" if configured else "cloudfront_distribution_metadata"
            if not required.issubset(value) or value.get("scope_area") != scope:
                failures.append(member + self.prefix[1:] + ".identity")
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Only this note's finite declared positions are public metadata."""
        return value in LITERALS.get(suffix, ())


def unknown_edge_notes(value: object, member: str) -> list[str]:
    """Require the note's actual AWS parent; foreign envelopes cannot borrow its rules."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict) or (contract := EdgeNoteContract.for_note(note)) is None:
                continue
            if row.get("scanner_id") != SCANNER or row.get("provider_id", "aws") != "aws":
                failures.append(member + contract.prefix[1:] + ".identity")
            else:
                failures.extend(contract.unknown_paths(note, member))
    return failures
