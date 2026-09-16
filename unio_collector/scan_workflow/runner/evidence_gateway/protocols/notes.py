from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class EvidenceNoteSource(Protocol):
    """Coverage-note writer methods required by scanner runtime."""

    def add_cached_evidence_note(
        self,
        definition: ScannerDefinition,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner definition."""
        ...

    def add_cached_evidence_note_for_scanner(
        self,
        scanner_id: str,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner identifier."""
        ...
