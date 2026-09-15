from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.scanner.implementation import ScannerImplementation


class CollectorScannerProtocol(Protocol):
    """Scanner surface allowed during collection-only execution."""

    def prepare(self, context: ScannerContext) -> None:
        """Prepare scanner-owned read-only collection."""
        ...

    def collect(self, context: ScannerContext) -> object:
        """Collect and return serialized scanner evidence input."""
        ...

    def describe_implementation(self) -> ScannerImplementation:
        """Return implementation metadata for the execution manifest."""
        ...
