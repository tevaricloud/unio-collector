"""Exact parent-bound Backup scanner configuration and analysis-policy callbacks."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.backup.fields import SCANNER
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

CONTROLS = {
    "backup_metadata_details": ("execution_detail", "max_detail_workers", "current_scan", "configured_value"),
    "backup_recovery_points": ("analysis_policy", "older_than_days", "finding_analysis", "configured_limit"),
    "backup_selection_details": ("configuration_limit", "selection_detail_mode", "current_scan", "configured_value"),
    "backup_resource_tags": ("configuration_limit", "collect_tags", "current_scan", "configured_value"),
}


class BackupNoteContract(AuditNoteContract):
    """Keep only fixed typed controls public; arbitrary summary/impact text protects whole."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area config_key result_scope", "string"),
        **fields("summary impact", "string", "free_text"),
        **fields("configured_limit", "integer", "summary_count"),
        **fields("configured_value", "configured"),
    }

    def __init__(self) -> None:
        """Bind one isolated provider or exact Backup note parent."""
        super().__init__(SCANNER)

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Select only the actual Backup scope and configuration discriminants."""
        return (
            cls()
            if (isinstance(value.get("scope_area"), str) and value["scope_area"] in CONTROLS)
            or (isinstance(value.get("config_key"), str) and value["config_key"].startswith(SCANNER + "."))
            else None
        )

    @classmethod
    def for_parent(cls, value: dict[str, Any], scanner: object, provider: object = "aws") -> Self | None:
        """Require the actual AWS Backup wrapper before note admission."""
        return cls.for_note(value) if scanner == SCANNER and provider == "aws" else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate exact configuration scalar types without accepting boolean counts."""
        if kind == "integer":
            return type(value) is int
        if kind == "configured":
            return type(value) in {str, bool, int}
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject incomplete, malformed or conflicting producer controls before transformation."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix == "" and isinstance(value, dict):
            scope = value.get("scope_area")
            controls = CONTROLS.get(scope) if isinstance(scope, str) else None
            valid = controls is not None
            if controls is not None:
                kind, config, result, field = controls
                keys = {"note_type", "scope_area", "summary", "config_key", "result_scope", field} | (
                    {"impact"} if config in {"selection_detail_mode", "collect_tags"} else set()
                )
                item = value.get(field)
                valid = (
                    set(value) == keys
                    and value.get("note_type") == kind
                    and value.get("config_key") == SCANNER + "." + config
                    and value.get("result_scope") == result
                )
                valid = valid and (
                    type(item) is int and (item > 0 if config == "max_detail_workers" else True)
                    if config in {"max_detail_workers", "older_than_days"}
                    else item == "summary"
                    if config == "selection_detail_mode"
                    else item is False
                )
            if not valid:
                failures.append(member + self.prefix[1:] + ".producer_controls")
        return failures

    def is_literal(self, suffix: str, value: object) -> bool:
        """Recognize finite Backup controls only at their declared field positions."""
        if not isinstance(value, str):
            return False
        return (
            (suffix == "scope_area" and isinstance(value, str) and value in CONTROLS)
            or (suffix == "note_type" and value in {"execution_detail", "analysis_policy", "configuration_limit"})
            or (suffix == "result_scope" and value in {"current_scan", "finding_analysis"})
            or (suffix == "config_key" and value in {SCANNER + "." + row[1] for row in CONTROLS.values()})
            or (suffix == "configured_value" and value == "summary")
        )


def unknown_backup_notes(value: object, member: str) -> list[str]:
    """Reject malformed or foreign notes before ordinary profile transformations."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict) or BackupNoteContract.for_note(note) is None:
                continue
            contract = BackupNoteContract.for_parent(note, row.get("scanner_id"), row.get("provider_id", "aws"))
            failures.extend(contract.unknown_paths(note, member) if contract is not None else [member + BackupNoteContract.prefix[1:] + ".identity"])
    return failures
