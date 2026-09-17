from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerLambdaGatewayRuntime


@dataclass(frozen=True)
class ScannerLambdaGateway:  # noqa: D101
    runtime: ScannerLambdaGatewayRuntime
    definition: ScannerDefinition

    def collect_function_inventory(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.collect_cached_lambda_function_inventory(self.definition)
