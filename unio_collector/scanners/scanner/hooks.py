"""Structural execution contract preserving an implementation-owned result type."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerAnalysisContract[ResultT](Protocol):
    """Describe execution hooks without exposing an application result model."""

    @property
    def metadata(self) -> ScannerDefinition:
        """Return the scanner's public registration metadata."""
        ...

    def prepare(self, context: ScannerContext) -> None:
        """Prepare implementation-owned collection."""
        ...

    def collect(self, context: ScannerContext) -> object:
        """Return implementation-owned evidence for serialisation."""
        ...

    def analyze(self, evidence: object, context: ScannerContext) -> ResultT:
        """Preserve the caller-owned result type without defining analysis policy."""
        ...
