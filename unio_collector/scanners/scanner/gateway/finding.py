from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerFindingGatewayRuntime


@dataclass(frozen=True)
class ScannerFindingGateway:  # noqa: D101
    runtime: ScannerFindingGatewayRuntime
    definition: ScannerDefinition

    def list_all(self) -> list[Finding]:  # noqa: D102
        return self.runtime.findings

    def update_at(self, index: int, finding: Finding) -> None:  # noqa: D102
        self.runtime.findings[index] = finding
