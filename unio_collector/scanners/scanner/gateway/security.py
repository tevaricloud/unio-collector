from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerSecurityGatewayRuntime


@dataclass(frozen=True)
class ScannerSecurityGateway:  # noqa: D101
    runtime: ScannerSecurityGatewayRuntime
    definition: ScannerDefinition

    @property
    def account_id(self) -> str:  # noqa: D102
        return str(self.runtime.runtime_state.account_id)

    @property
    def session(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.runtime_state.session

    def create_audit_context(self, collector_name: str) -> Any:  # noqa: ANN401, D102
        return self.runtime.create_audit_context(
            self.definition,
            collector_name,
        )

    def create_client(  # noqa: D102
        self,
        service_name: str,
        *,
        region_name: str | None = None,
        collector_name: str,
    ) -> Any:  # noqa: ANN401
        return self.runtime.runtime_state.session.create_client(
            service_name,
            region_name=region_name,
            audit_context=self.create_audit_context(collector_name),
        )

    def create_regional_inventory_collector(  # noqa: D102
        self,
        collector_type: type[Any],
        *,
        collector_name: str,
        selected_regions: list[str] | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        return collector_type(
            self.runtime.runtime_state.session,
            account_id=self.account_id,
            audit_context=self.create_audit_context(collector_name),
            selected_regions=(self.runtime.runtime_state.get_selected_regions() if selected_regions is None else selected_regions),
            **kwargs,
        )

    def get_selected_regions(self) -> list[str] | None:  # noqa: D102
        return self.runtime.runtime_state.get_selected_regions()
