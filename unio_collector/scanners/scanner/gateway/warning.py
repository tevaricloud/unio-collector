from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerWarningGatewayRuntime


@dataclass(frozen=True)
class ScannerWarningGateway:  # noqa: D101
    runtime: ScannerWarningGatewayRuntime
    definition: ScannerDefinition

    def add(self, warning: str) -> None:  # noqa: D102
        self.runtime.add_scanner_warning(self.definition.scanner_id, warning)

    def add_coverage_note(self, note: dict[str, Any]) -> None:  # noqa: D102
        self.runtime.add_scanner_coverage_note(self.definition.scanner_id, note)
