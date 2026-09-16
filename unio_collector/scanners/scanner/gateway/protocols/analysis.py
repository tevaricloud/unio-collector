from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.reference_time import AnalysisReferenceTime


class ScannerAnalysisGatewayRuntime(Protocol):
    """Runtime surface required by the analysis gateway."""

    @property
    def analysis_reference_time(self) -> AnalysisReferenceTime:
        """Return the stable reference time for scanner analysis."""
        ...
