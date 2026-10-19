"""Closed current-scan execution callback emitted by the ECR posture collector."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

SCANNER = "ecr-image-scan-posture-review"
LITERALS = {"note_type": {"execution_detail"}, "scope_area": {"ecr_image_scanning"}, "result_scope": {"current_scan"}}


class EcrNoteContract(AuditNoteContract):
    """Preserve typed counts and region policy while tokenizing arbitrary prose."""

    fields: ClassVar = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area result_scope", "note_literal"),
        **fields("repository_count registry_configuration_count warning_count", "count", "summary_count"),
        **fields("regions", "array"),
        **fields("regions[]", "string", "region"),
        **fields("summary impact", "string", "free_text"),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> EcrNoteContract | None:
        """Select the exact ECR callback scope; parent admission is verified separately."""
        return cls(SCANNER) if value.get("scope_area") == "ecr_image_scanning" else None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Do not let strict omission conceal invalid controls or unknown descendants."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and not self.is_literal(suffix, value):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Only fixed callback discriminants are public constants."""
        return isinstance(value, str) and suffix in LITERALS and value in LITERALS[suffix]


def unknown_exposure_notes(value: object, member: str) -> list[str]:
    """Bind each ECR callback to the actual containing scanner-results identity."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict):
        return []
    rows = value.get("scanner_results")
    if not isinstance(rows, list):
        return []
    failures = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        failures.extend(_row_note_failures(row, member))
    return failures


def _row_note_failures(row: dict[str, Any], member: str) -> list[str]:
    """Validate one parent identity and all of its emitted callback notes."""
    failures = []
    for note in row["coverage_notes"]:
        if not isinstance(note, dict):
            if row.get("scanner_id") == SCANNER:
                failures.append(member + ".scanner_results[].coverage_notes[]")
            continue
        contract = EcrNoteContract.for_note(note)
        if contract is not None and row.get("scanner_id") != SCANNER:
            failures.append(member + ".scanner_results[].coverage_notes[].identity")
        elif contract is not None:
            failures.extend(contract.unknown_paths(note, member))
        elif row.get("scanner_id") == SCANNER:
            failures.append(member + ".scanner_results[].coverage_notes[].scope")

    return failures
