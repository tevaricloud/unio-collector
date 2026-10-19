"""Exact fast-path and API-degradation notes emitted by the tagging wrapper."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.privacy.tagging.fields import SCANNER

LITERALS = {
    "note_type": {"fast_path_source", "api_degradation"},
    "source": {"resource_groups_tagging_api"},
    "status": {"completed", "partial", "permission_denied", "unavailable", "disabled"},
    "status_label": {"completed", "partial", "permission denied", "unavailable", "disabled"},
    "fallback_source": {"direct_ec2_inventory"},
    "config_key": {SCANNER + ".use_resource_groups_tagging_api"},
    "scanner_id": {SCANNER},
    "api_action": {"elbv2:DescribeTags", "elbv2:DescribeTargetGroups", "elbv2:DescribeTargetHealth"},
    "error_classification": {"partial_collection"},
    "outcome": {"partial"},
    "resource_type": {"Load balancer", "Target group"},
    "affected_fields[]": {"tags", "target_groups", "target_health"},
    "evidence_categories[]": {"tag association", "resource association"},
}
FAST = {
    "note_type",
    "summary",
    "source",
    "status",
    "status_label",
    "records_returned",
    "regions_scanned",
    "errors",
    "limitations",
    "fallback_source",
    "impact",
    "config_key",
}
API = {
    "note_type",
    "scanner_id",
    "region",
    "api_action",
    "resource_id",
    "resource_type",
    "affected_fields",
    "evidence_categories",
    "requested_account_id",
    "requested_region",
    "safe_scope",
    "outcome",
    "error_classification",
    "occurrence_count",
}


class TaggingNoteContract(AuditNoteContract):
    """Preserve finite controls, protecting identifiers and arbitrary diagnostics in full."""

    fields: ClassVar = {
        "": ("object", "safe_metadata", False),
        **fields(" ".join(key for key in LITERALS if not key.endswith("[]")), "string"),
        **fields("summary impact errors[] limitations[]", "string", "free_text"),
        **fields("regions_scanned errors limitations affected_fields evidence_categories", "array"),
        **fields("affected_fields[] evidence_categories[]", "string"),
        **fields("region regions_scanned[]", "string", "region"),
        **fields("requested_region", "string", "region", nullable=True),
        **fields("requested_account_id", "string", "aws_account_id", nullable=True),
        **fields("resource_id", "string", "arn_or_name", nullable=True),
        **fields("safe_scope", "string", "free_text", nullable=True),
        **fields("records_returned occurrence_count", "count", "summary_count"),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Recognize exact callback discriminators without granting foreign-parent admission."""
        return (
            cls(SCANNER)
            if value.get("source") == "resource_groups_tagging_api"
            or value.get("scanner_id") == SCANNER
            or value.get("config_key") == SCANNER + ".use_resource_groups_tagging_api"
            else None
        )

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Do not let one note kind borrow the other kind's fields or foreign controls."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and (not isinstance(value, str) or value not in LITERALS[suffix]):
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "" and isinstance(value, dict):
            fast = value.get("note_type") == "fast_path_source"
            allowed = FAST if fast else API
            required = {"note_type", "source", "status", "records_returned", "regions_scanned", "errors", "limitations", "fallback_source"} if fast else API
            if not set(value).issubset(allowed) or not required.issubset(value):
                failures.append(member + self.prefix[1:] + ".identity")
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """No arbitrary free text or resource identifiers obtain literal treatment."""
        return value in LITERALS.get(suffix, ())


def unknown_tagging_notes(value: object, member: str) -> list[str]:
    """Require the real AWS parent and reject changed callback discriminators early."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict):
                continue
            contract = TaggingNoteContract.for_note(note)
            if row.get("scanner_id") == SCANNER:
                contract = TaggingNoteContract(SCANNER)
            if contract is None:
                continue
            if row.get("scanner_id") != SCANNER or row.get("provider_id", "aws") != "aws":
                failures.append(member + contract.prefix[1:] + ".identity")
            else:
                failures.extend(contract.unknown_paths(note, member))
    return failures
