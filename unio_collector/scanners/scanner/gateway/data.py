from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerDataGatewayRuntime


@dataclass(frozen=True)
class ScannerDataGateway:  # noqa: D101
    runtime: ScannerDataGatewayRuntime
    definition: ScannerDefinition

    def set(self, key: str, value: Any) -> None:  # noqa: ANN401, D102
        self.runtime.scanner_data[key] = value

    def get(self, key: str, default: object = None) -> object:  # noqa: D102
        return self.runtime.scanner_data.get(key, default)
