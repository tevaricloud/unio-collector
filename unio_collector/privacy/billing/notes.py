"""Exact configuration-limit callbacks from the actual billing collector."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

SCANNER = "billing-alerts-and-budgets-review"
SCOPES = {"budget_notification_subscribers": ("subscriber_detail_mode", "summary"), "billing_monitoring_controls": ("monitor_detail_mode", "budgets-only")}
LITERALS = {
    "note_type": {"configuration_limit"},
    "result_scope": {"current_scan"},
    "scope_area": set(SCOPES),
    "config_key": {SCANNER + "." + pair[0] for pair in SCOPES.values()},
    "configured_value": {pair[1] for pair in SCOPES.values()},
}


class BillingNoteContract(AuditNoteContract):
    """Protect prose while binding exact configuration controls to their owning scanner."""

    fields: ClassVar = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area result_scope config_key configured_value", "note_literal"),
        **fields("summary impact", "string", "free_text"),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> BillingNoteContract | None:
        """Select both discriminants so changing one cannot evade validation."""
        scope, key = value.get("scope_area"), value.get("config_key")
        return cls(SCANNER) if (isinstance(scope, str) and scope in SCOPES) or (isinstance(key, str) and key in LITERALS["config_key"]) else None

    def is_literal(self, suffix: str, value: object) -> bool:
        """Expose only five declared fields with their finite producer vocabularies."""
        return isinstance(value, str) and value in LITERALS.get(suffix, set())

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject unknown/null/wrongly typed notes and inconsistent configured modes."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and not self.is_literal(suffix, value):
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "" and isinstance(value, dict):
            if set(value) != set(self.fields) - {""}:
                failures.append(member + self.prefix[1:] + ".fields")
            expected = SCOPES.get(str(value.get("scope_area")))
            if expected is None or value.get("config_key") != SCANNER + "." + expected[0] or value.get("configured_value") != expected[1]:
                failures.append(member + self.prefix[1:] + ".configuration")
        return failures


def unknown_billing_notes(value: object, member: str) -> list[str]:
    """Bind callback contracts to the actual parent scanner-results record."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict):
        return []
    rows = value.get("scanner_results")
    if not isinstance(rows, list):
        return []
    return [path for row in rows if isinstance(row, dict) for path in _row_failures(row, member)]


def _row_failures(row: dict[str, Any], member: str) -> list[str]:
    """Validate each configured billing callback before profile removal."""
    failures = []
    notes = row.get("coverage_notes", [])
    if not isinstance(notes, list):
        return [member + ".scanner_results[].coverage_notes"] if row.get("scanner_id") == SCANNER else []
    for note in notes:
        if not isinstance(note, dict):
            if row.get("scanner_id") == SCANNER:
                failures.append(member + ".scanner_results[].coverage_notes[]")
            continue
        contract = BillingNoteContract.for_note(note)
        if contract is not None and row.get("scanner_id") != SCANNER:
            failures.append(member + ".scanner_results[].coverage_notes[].identity")
        elif contract is not None:
            failures.extend(contract.unknown_paths(note, member))
        elif row.get("scanner_id") == SCANNER:
            failures.append(member + ".scanner_results[].coverage_notes[].scope")
    return failures
