"""Closed callback notes bound to IAM scanner identities and actual note scopes."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

ACCOUNT_SCANNER = "iam-account-security-review"
CENTER_SCANNER = "iam-identity-center-visibility-review"
OPTION_KEY = "scanners.iam-account-security-review.policy_detail_mode"
COMMON = {"": ("object", "safe_metadata", False), **fields("note_type result_scope", "note_literal"), **fields("summary impact", "string", "free_text")}
OPTION = {**COMMON, **fields("config_key configured_value", "note_literal")}
PASSWORD = {
    **COMMON,
    **fields("scope_area status", "note_literal"),
    **fields("minimum_password_length", "count", "summary_count"),
    **fields("max_password_age password_reuse_prevention", "count", "summary_count", nullable=True),
    **fields("require_symbols require_numbers require_uppercase require_lowercase", "boolean"),
    **fields("allow_users_to_change_password hard_expiry", "boolean", nullable=True),
}
CENTER = {**COMMON, **fields("scope_area status", "note_literal"), **fields("instance_count permission_set_count warning_count", "count", "summary_count")}
LITERALS = {
    "note_type": {"execution_detail"},
    "result_scope": {"current_scan"},
    "status": {"visible", "not_visible"},
    "configured_value": {"full", "off", "administrator-access-only"},
    "config_key": {OPTION_KEY},
    "scope_area": {"iam_password_policy", "iam_identity_center"},
}


class IdentityNoteContract(AuditNoteContract):
    """Require exact note kind/scope and protect whole arbitrary explanatory text."""

    fields: ClassVar = COMMON

    def __init__(self, scope: str) -> None:
        """Choose exactly one actual callback shape, without pooling allowed fields."""
        self.scope = scope
        self.scanner = CENTER_SCANNER if scope == "iam_identity_center" else ACCOUNT_SCANNER

    @classmethod
    def for_note(cls, value: dict[str, Any], *, scanner_id: str | None = None) -> IdentityNoteContract | None:
        """Select only known callback scopes and require their originating scanner."""
        scope = "option" if value.get("config_key") == OPTION_KEY else value.get("scope_area")
        if not isinstance(scope, str) or scope not in {"option", "iam_password_policy", "iam_identity_center"}:
            return None
        from unio_collector.privacy.identity.option import OptionNoteContract  # noqa: PLC0415
        from unio_collector.privacy.identity.password import PasswordNoteContract  # noqa: PLC0415
        from unio_collector.privacy.identity.visibility import VisibilityNoteContract  # noqa: PLC0415

        contract = {"option": OptionNoteContract, "iam_password_policy": PasswordNoteContract, "iam_identity_center": VisibilityNoteContract}[scope](scope)
        if scanner_id is not None and scanner_id != contract.scanner:
            message = "IAM callback note conflicts with its originating scanner identity."
            raise ValueError(message)
        return contract

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject unknown counters, nullable controls and foreign literal discriminants."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and not self.is_literal(suffix, value):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Mask only fixed callback metadata for the exact selected scope."""
        if suffix == "scope_area":
            return value == self.scope
        return isinstance(value, str) and suffix in LITERALS and value in LITERALS[suffix]


def unknown_identity_notes(value: object, member: str) -> list[str]:
    """Bind callback preflight to each actual parent scanner-results record."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict):
        return []
    rows = value.get("scanner_results")
    if not isinstance(rows, list):
        return []
    failures = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        scanner = row.get("scanner_id")
        for note in row["coverage_notes"]:
            if not isinstance(note, dict):
                continue
            try:
                contract = IdentityNoteContract.for_note(note, scanner_id=str(scanner))
            except ValueError:
                failures.append(member + ".scanner_results[].coverage_notes[].identity")
                continue
            if contract is not None:
                failures.extend(contract.unknown_paths(note, member))
            elif scanner in {ACCOUNT_SCANNER, CENTER_SCANNER}:
                failures.append(member + ".scanner_results[].coverage_notes[].scope")
    return failures
