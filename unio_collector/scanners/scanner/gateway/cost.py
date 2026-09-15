from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerCostGatewayRuntime


@dataclass(frozen=True)
class ScannerCostGateway:  # noqa: D101
    runtime: ScannerCostGatewayRuntime
    definition: ScannerDefinition

    def collect_service_costs(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.collect_cached_service_costs(self.definition)

    def collect_daily_costs(  # noqa: D102
        self,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> Any:  # noqa: ANN401
        return self.runtime.collect_cached_daily_costs(
            self.definition,
            group_keys=group_keys,
        )

    def record_service_delta_context(  # noqa: D102
        self,
        *,
        previous_period: Any,  # noqa: ANN401
        current_period: Any,  # noqa: ANN401
        service_deltas: Any,  # noqa: ANN401
    ) -> None:
        self.runtime.previous_period = previous_period
        self.runtime.current_period = current_period
        self.runtime.service_deltas = service_deltas
        if hasattr(self.runtime, "financial_context_restored"):
            cast("Any", self.runtime).financial_context_restored = True

    def get_current_period(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.current_period
