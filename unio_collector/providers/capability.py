from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.providers.types import ProviderPillarId, normalize_string_tuple


@dataclass(frozen=True)
class ProviderScannerCapability:
    """Provider-aware scanner capability metadata for future selection layers."""

    scanner_id: str
    provider_ids: tuple[str, ...]
    pillars: tuple[ProviderPillarId, ...]
    required_permissions: tuple[str, ...]
    evidence_domains: tuple[str, ...]
    output_finding_types: tuple[str, ...]
    scope_types: tuple[str, ...] = ()
    location_types: tuple[str, ...] = ()
    api_domains: tuple[str, ...] = ()
    maturity: str = "unknown"
    limitations: tuple[str, ...] = ()
    offline_fixture_supported: bool = False
    live_runtime_required: bool = True

    def __post_init__(self) -> None:
        """Normalize immutable capability metadata collections."""
        object.__setattr__(self, "provider_ids", normalize_string_tuple(self.provider_ids))
        object.__setattr__(
            self,
            "required_permissions",
            normalize_string_tuple(self.required_permissions),
        )
        object.__setattr__(
            self,
            "evidence_domains",
            normalize_string_tuple(self.evidence_domains),
        )
        object.__setattr__(
            self,
            "output_finding_types",
            normalize_string_tuple(self.output_finding_types),
        )
        object.__setattr__(self, "scope_types", normalize_string_tuple(self.scope_types))
        object.__setattr__(
            self,
            "location_types",
            normalize_string_tuple(self.location_types),
        )
        object.__setattr__(self, "api_domains", normalize_string_tuple(self.api_domains))
        object.__setattr__(self, "limitations", normalize_string_tuple(self.limitations))
