"""Closed configured instance-metric cap note from the actual EC2 wrapper."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract

SCANNER = "ec2-idle-instance-review"
OPTION = SCANNER + ".max_instances_per_region"
SCOPE = "ec2_running_instance_metrics"
LITERALS = {"note_type": "configuration_limit", "scope_area": SCOPE, "config_key": OPTION, "result_scope": "current_scan"}


class ComputeLimitNoteContract(AuditNoteContract):
    """Bind only the one producer scope/key pair; keep arbitrary prose protected."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **dict.fromkeys(LITERALS, ("note_literal", "safe_metadata", False)),
        "configured_limit": ("count", "summary_count", False),
        "summary": ("string", "free_text", False),
        "impact": ("string", "free_text", False),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Select validation by matching key or scope; reject conflicting discriminants."""
        return cls(SCANNER) if value.get("config_key") == OPTION or value.get("scope_area") == SCOPE else None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Admit exact literals, positive integral limits and no extra children."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and value != LITERALS[suffix]:
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "configured_limit" and (type(value) is not int or value < 1):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Mask only exact producer control values, never summary or impact text."""
        return suffix in LITERALS and value == LITERALS[suffix]


def unknown_compute_notes(value: object, member: str) -> list[str]:
    """Reject even well-formed cap notes under a foreign originating scanner."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict):
        return []
    rows = value.get("scanner_results")
    if not isinstance(rows, list):
        return []
    failures = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        failures.extend(
            member + ".scanner_results[].coverage_notes[].identity"
            for note in row["coverage_notes"]
            if isinstance(note, dict) and ComputeLimitNoteContract.for_note(note) is not None and row.get("scanner_id") != SCANNER
        )
    return failures
