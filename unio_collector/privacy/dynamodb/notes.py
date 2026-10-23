"""Exact DynamoDB configuration callbacks, bound to their originating wrapper."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.dynamodb.fields import SCANNER
from unio_collector.privacy.s3.fields import fields

CONTROLS = {
    "max_table_workers": ("execution_detail", "dynamodb_table_metadata"),
    "table_detail_regional_mode": ("configuration_limit", "dynamodb_table_metadata"),
    "retention_detail_mode": ("configuration_limit", "dynamodb_retention_metadata"),
    "autoscaling_detail_mode": ("configuration_limit", "dynamodb_application_autoscaling_metadata"),
    "metric_detail_mode": ("configuration_limit", "dynamodb_cloudwatch_metrics"),
}


class DynamoNoteContract(AuditNoteContract):
    """Preserve only complete typed fixed controls; protect summary and impact whole."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area config_key result_scope", "string"),
        **fields("summary impact", "string", "free_text"),
        **fields("configured_value", "configured"),
        **fields("table_count attempted_region_count detail_region_count summary_region_count", "count", "summary_count"),
        **fields("detail_regions summary_regions", "array"),
        **fields("detail_regions[] summary_regions[]", "string", "region"),
    }

    def __init__(self) -> None:
        """Bind exact DynamoDB configuration-note ownership."""
        super().__init__(SCANNER)

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Recognise fixed scopes or the exact scanner configuration prefix."""
        return (
            cls()
            if (isinstance(value.get("scope_area"), str) and value["scope_area"] in {row[1] for row in CONTROLS.values()})
            or (isinstance(value.get("config_key"), str) and value["config_key"].startswith(SCANNER + "."))
            else None
        )

    @classmethod
    def for_parent(cls, value: dict[str, Any], scanner: object, provider: object = "aws") -> Self | None:
        """Require the actual originating AWS wrapper before note admission."""
        return cls.for_note(value) if scanner == SCANNER and provider == "aws" else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        return type(value) in {str, int} if kind == "configured" else super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject incomplete, conflicting or malformed controls before protection."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix == "" and isinstance(value, dict):
            config_key = value.get("config_key")
            config = config_key.removeprefix(SCANNER + ".") if isinstance(config_key, str) else ""
            control = CONTROLS.get(config)
            valid = False
            if control is not None:
                note_type, scope = control
                keys = {"note_type", "scope_area", "summary", "impact", "config_key", "configured_value", "result_scope"}
                if config == "max_table_workers":
                    keys.add("table_count")
                if config == "table_detail_regional_mode":
                    keys |= {"attempted_region_count", "detail_region_count", "summary_region_count", "detail_regions", "summary_regions"}
                item = value.get("configured_value")
                valid = (
                    set(value) == keys
                    and value.get("scope_area") == scope
                    and value.get("note_type") == note_type
                    and value.get("config_key") == SCANNER + "." + config
                    and value.get("result_scope") == "current_scan"
                )
                valid = valid and (
                    type(item) is int and item > 0
                    if config == "max_table_workers"
                    else item == "billing-active"
                    if config == "table_detail_regional_mode"
                    else item == "summary"
                )
                if valid and config == "table_detail_regional_mode":
                    valid = (
                        all(
                            isinstance(value.get(key), list) and value.get(key.replace("regions", "region_count")) == len(value[key])
                            for key in ("detail_regions", "summary_regions")
                        )
                        and value["attempted_region_count"] == value["detail_region_count"] + value["summary_region_count"]
                    )
            if not valid:
                failures.append(member + self.prefix[1:] + ".producer_controls")
        return failures

    def is_literal(self, suffix: str, value: object) -> bool:
        """Keep fixed callback controls separate from arbitrary summary text."""
        if not isinstance(value, str):
            return False
        return (
            (suffix == "scope_area" and value in {row[1] for row in CONTROLS.values()})
            or (suffix == "note_type" and value in {"configuration_limit", "execution_detail"})
            or (suffix == "result_scope" and value == "current_scan")
            or (suffix == "config_key" and value in {SCANNER + "." + config for config in CONTROLS})
            or (suffix == "configured_value" and value in {"summary", "billing-active"})
        )


def unknown_dynamo_notes(value: object, member: str) -> list[str]:
    """Reject unknown or foreign DynamoDB controls before ordinary transformations."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict) or DynamoNoteContract.for_note(note) is None:
                continue
            contract = DynamoNoteContract.for_parent(note, row.get("scanner_id"), row.get("provider_id", "aws"))
            failures.extend(contract.unknown_paths(note, member) if contract is not None else [member + DynamoNoteContract.prefix[1:] + ".identity"])
    return failures
