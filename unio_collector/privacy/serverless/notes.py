"""Exact parent-bound SQS polling operational-cap callback contract."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.privacy.serverless.polling import SCANNER

LITERALS = {
    "note_type": "configuration_limit",
    "scope_area": "sqs_lambda_event_source_mappings",
    "config_key": SCANNER + ".max_mappings_per_region",
    "result_scope": "current_scan",
}


class PollingNoteContract(AuditNoteContract):
    """Preserve only fixed controls while protecting arbitrary summary and impact text."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area config_key result_scope", "note_literal"),
        **fields("configured_limit", "positive", "summary_count"),
        **fields("summary impact", "string", "free_text"),
    }

    def __init__(self) -> None:
        """Bind the one registered cap producer."""
        super().__init__(SCANNER)

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Select only this exact scope/config identity; no prose-based routing."""
        return cls() if value.get("scope_area") == LITERALS["scope_area"] or value.get("config_key") == LITERALS["config_key"] else None

    @classmethod
    def for_parent(cls, value: dict[str, Any], scanner: object, provider: object = "aws") -> Self | None:
        """Require its actual AWS parent before normalizing any note controls."""
        return cls.for_note(value) if scanner == SCANNER and provider == "aws" else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "positive":
            return type(value) is int and value > 0
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require every producer key, exact finite controls and no undeclared member."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix == "" and isinstance(value, dict) and set(value) != set(LITERALS) | {"configured_limit", "summary", "impact"}:
            failures.append(member + self.prefix[1:])
        if suffix in LITERALS and not self.is_literal(suffix, value):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def is_literal(self, suffix: str, value: object) -> bool:
        """Keep only the actual producer's fixed control at its exact position."""
        return suffix in LITERALS and value == LITERALS[suffix]


def unknown_polling_notes(value: object, member: str) -> list[str]:
    """Reject foreign/malformed cap notes before strict transformation can remove data."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict) or PollingNoteContract.for_note(note) is None:
                continue
            contract = PollingNoteContract.for_parent(note, row.get("scanner_id"), row.get("provider_id", "aws"))
            failures.extend(contract.unknown_paths(note, member) if contract is not None else [member + PollingNoteContract.prefix[1:] + ".identity"])
    return failures
