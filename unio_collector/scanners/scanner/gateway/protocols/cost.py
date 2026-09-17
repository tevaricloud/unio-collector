from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerCostGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner cost gateways."""

    @property
    def previous_period(self) -> CostPeriod: ...  # noqa: D102

    @previous_period.setter
    def previous_period(self, value: CostPeriod) -> None: ...

    @property
    def current_period(self) -> CostPeriod: ...  # noqa: D102

    @current_period.setter
    def current_period(self, value: CostPeriod) -> None: ...

    @property
    def service_deltas(self) -> list[ServiceSpendDelta]: ...  # noqa: D102

    @service_deltas.setter
    def service_deltas(self, value: list[ServiceSpendDelta]) -> None: ...

    def collect_cached_service_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult: ...

    def collect_cached_daily_costs(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]: ...

    def collect_cached_daily_costs_with_context(  # noqa: D102
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]: ...
