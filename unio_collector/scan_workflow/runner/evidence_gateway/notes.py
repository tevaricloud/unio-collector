from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        EvidenceNoteSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class EvidenceNoteGateway:
    """Delegate scanner coverage note writes to the evidence note source."""

    def __init__(self, source: EvidenceNoteSource) -> None:  # noqa: D107
        self._source = source

    def add_cached_evidence_note(
        self,
        definition: ScannerDefinition,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner definition."""
        self._source.add_cached_evidence_note(
            definition,
            namespace=namespace,
            label=label,
            access_status=access_status,
        )

    def add_cached_evidence_note_for_scanner(
        self,
        scanner_id: str,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        """Write a cached-evidence coverage note for a scanner identifier."""
        self._source.add_cached_evidence_note_for_scanner(
            scanner_id,
            namespace=namespace,
            label=label,
            access_status=access_status,
        )
