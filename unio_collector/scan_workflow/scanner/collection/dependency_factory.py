from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.runtime.dependencies import (
    ScannerRuntimeDependencies,
)
from unio_collector.scanners.collection.path_factory import (
    build_scanner_from_collector_factory_path,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scanners.scanner.collection_protocol import CollectorScannerProtocol


class ScannerCollectionDependencyFactory:
    """Build scanner dependencies for collection-only scheduler execution."""

    def create_dependencies(
        self,
        *,
        progress: Callable[[ScanProgressEvent], None] | None,
        scanner_total: int | None,
    ) -> ScannerRuntimeDependencies[CollectorScannerProtocol]:
        """Create collection-only scanner dependencies."""
        return ScannerRuntimeDependencies(
            scanner_factory=build_scanner_from_collector_factory_path,
            progress=progress,
            scanner_total=scanner_total,
        )
