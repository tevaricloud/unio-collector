"""Closed actual same-scan cache reuse and deadline callback contracts."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

REUSE = "cached_evidence_reuse"
DEADLINE = "scanner_deadline_limited_evidence"
KINDS = frozenset({REUSE, DEADLINE})
COMMON = frozenset({"note_type", "cache_label", "cache_namespace", "summary", "result_scope", "impact"})


class CacheNoteContract(AuditNoteContract):
    """Admit only complete producer shapes under a known AWS collector parent."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type cache_access_status cache_action result_scope", "note_literal"),
        **fields("cache_label cache_namespace", "cache_text", "free_text"),
        **fields("summary impact", "string", "free_text"),
    }

    def __init__(self, kind: str) -> None:
        """Bind the exact operational callback kind without inferring from prose."""
        super().__init__("")
        self.kind = kind

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Select only the two actual discriminants; arbitrary kinds stay unknown."""
        kind = value.get("note_type")
        return cls(kind) if isinstance(kind, str) and kind in KINDS else None

    @classmethod
    def for_parent(cls, value: dict[str, Any], scanner: object, provider: object = "aws") -> Self | None:
        """Require the finite live collector registry and exact AWS provider binding."""
        return cls.for_note(value) if isinstance(scanner, str) and scanner in COLLECTOR_SCANNER_CLASS_PATHS and provider == "aws" else None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Require nonempty protected labels/namespaces and exact declared scalar types."""
        if kind == "cache_text":
            return isinstance(value, str) and bool(value)
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Check exact keys, types, scopes and the actual hit/waited action pairing."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        path = member + self.prefix[1:] + ("." + suffix if suffix else "")
        if suffix == "" and isinstance(value, dict):
            required = COMMON | {"cache_access_status", "cache_action"} if self.kind == REUSE else COMMON
            failures.extend(path + "." + key for key in sorted(set(value) ^ required))
            if (
                not failures
                and self.kind == REUSE
                and (value["cache_access_status"], value["cache_action"]) not in {("hit", "reused"), ("waited", "waited for")}
            ):
                failures.append(path + ".cache_action")
        if self.fields.get(suffix, ("", "", False))[0] == "note_literal" and not self.is_literal(suffix, value):
            failures.append(path)
        return failures

    def is_literal(self, suffix: str, value: object) -> bool:
        """Keep only fixed producer controls public, never labels, namespaces or prose."""
        literals = {
            "note_type": {self.kind},
            "result_scope": {"same_scan" if self.kind == REUSE else "current_scan"},
            "cache_access_status": {"hit", "waited"} if self.kind == REUSE else set(),
            "cache_action": {"reused", "waited for"} if self.kind == REUSE else set(),
        }
        return isinstance(value, str) and value in literals.get(suffix, set())
