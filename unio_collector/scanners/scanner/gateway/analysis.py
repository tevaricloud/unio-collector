from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import date, datetime

    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import (
        ScannerAnalysisGatewayRuntime,
    )


@dataclass(frozen=True)
class ScannerAnalysisGateway:
    """Load full-application analyzer symbols for scanner analysis paths."""

    runtime: ScannerAnalysisGatewayRuntime
    definition: ScannerDefinition

    def load_symbol(self, module_name: str, attribute_name: str) -> Any:  # noqa: ANN401
        """Return an analyzer symbol for full scan execution."""
        del self
        return load_analysis_symbol(module_name, attribute_name)

    @property
    def reference_instant(self) -> datetime:
        """Return the stable UTC instant for this scanner analysis."""
        return self.runtime.analysis_reference_time.instant

    @property
    def reference_date(self) -> date:
        """Return the stable UTC date for date-based scanner policy."""
        return self.runtime.analysis_reference_time.date

    @property
    def reference_time_source(self) -> str:
        """Return provenance for the scanner analysis reference time."""
        return self.runtime.analysis_reference_time.source


def load_analysis_symbol(module_name: str, attribute_name: str) -> Any:  # noqa: ANN401
    """Return an analyzer symbol for full scan execution."""
    return getattr(import_module(module_name), attribute_name)
