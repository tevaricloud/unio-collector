from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.providers.capability import ProviderScannerCapability


@dataclass(frozen=True)
class ProviderScannerCatalog:
    """Provider-owned scanner catalog metadata."""

    provider_id: str
    capabilities: tuple[ProviderScannerCapability, ...]
    live_execution_supported: bool = False
    scanner_definitions: tuple[Any, ...] = ()

    def get_capability(self, scanner_id: str) -> ProviderScannerCapability | None:
        """Return provider-aware scanner capability metadata when present."""
        for capability in self.capabilities:
            if capability.scanner_id == scanner_id:
                return capability
        return None
