from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.options import (
    parse_scanner_option_bool,
    parse_scanner_option_int,
)

if TYPE_CHECKING:
    from unio_collector.core.scan.period import ScanPeriod
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerOptionsGatewayRuntime


@dataclass(frozen=True)
class ScannerOptionsGateway:  # noqa: D101
    runtime: ScannerOptionsGatewayRuntime
    definition: ScannerDefinition

    def get(self, key: str, default: object) -> object:  # noqa: D102
        return self.get_for_scanner(self.definition.scanner_id, key, default)

    def get_for_scanner(  # noqa: D102
        self,
        scanner_id: str,
        key: str,
        default: object,
    ) -> object:
        return self.runtime.runtime_state.get_scanner_option(
            scanner_id,
            key,
            default,
        )

    def get_bool(self, key: str, *, default: bool) -> bool:  # noqa: D102
        return parse_scanner_option_bool(self.get(key, default))

    def get_int(self, key: str, default: int) -> int:  # noqa: D102
        return parse_scanner_option_int(self.get(key, default))

    def get_runtime_max_workers(self, default: int = 16) -> int:  # noqa: D102
        runtime_config = getattr(self.runtime.runtime_state.config, "runtime", None)
        value = getattr(runtime_config, "max_workers", default)
        if isinstance(value, int):
            return value
        return parse_scanner_option_int(value)

    def get_scan_config_value(self, key: str, default: object) -> object:  # noqa: D102
        return getattr(self.runtime.runtime_state.config, key, default)

    def get_config(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.runtime_state.config

    def get_decimal_scan_config_value(self, key: str, default: Decimal) -> Decimal:  # noqa: D102
        value = getattr(self.runtime.runtime_state.config, key, default)
        if isinstance(value, Decimal):
            return value
        if isinstance(value, (int, float, str)):
            return Decimal(str(value))
        return default

    def get_scan_period(self) -> ScanPeriod:  # noqa: D102
        return self.runtime.runtime_state.config.scan_period

    def get_selected_regions(self) -> list[str]:  # noqa: D102
        return self.runtime.runtime_state.get_selected_regions() or []

    def has_explicit_region_scope(self) -> bool:  # noqa: D102
        return self.runtime.runtime_state.has_explicit_region_scope()

    def get_required_tags(self) -> list[str]:  # noqa: D102
        value = getattr(self.runtime.runtime_state.config, "required_tags", [])
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, tuple):
            return [str(item) for item in value]
        return []
