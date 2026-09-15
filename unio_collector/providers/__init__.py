"""Provider contracts package wayfinding.

owns: provider-neutral identity, scope, location, resource, evidence, scanner capability, and finding metadata contracts.
must not import: SDKs, provider runtime modules, scanners, report writers, or CLI modules.
protects: provider-neutral API and additive provider selection path.
start here: docs/provider-architecture.md, docs/provider-extensibility-reconciliation.md, selection.py, and contract modules.
focused tests: tests/providers and tests/architecture/test_provider_boundaries.py.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.providers.capability import ProviderScannerCapability
from unio_collector.providers.evidence import ProviderEvidenceMetadata
from unio_collector.providers.finding import ProviderFindingMetadata
from unio_collector.providers.identity import ProviderIdentity
from unio_collector.providers.location import ProviderLocation
from unio_collector.providers.registry import ProviderIdentityRegistry
from unio_collector.providers.resource import ProviderResourceIdentity
from unio_collector.providers.runtime.contract import ProviderRuntimeProtocol
from unio_collector.providers.runtime.descriptor import ProviderRuntimeDescriptor
from unio_collector.providers.runtime.registry import ProviderRuntimeRegistry
from unio_collector.providers.scanner_catalog import ProviderScannerCatalog
from unio_collector.providers.scope import ProviderAccountScope
from unio_collector.providers.types import (
    ProviderCollectionStatus,
    ProviderLocationType,
    ProviderPillarId,
    ProviderScopeType,
)

if TYPE_CHECKING:
    from unio_collector.providers.report_metadata import ReportProviderMetadata

__all__ = [
    "ProviderAccountScope",
    "ProviderCollectionStatus",
    "ProviderEvidenceMetadata",
    "ProviderFindingMetadata",
    "ProviderIdentity",
    "ProviderIdentityRegistry",
    "ProviderLocation",
    "ProviderLocationType",
    "ProviderPillarId",
    "ProviderResourceIdentity",
    "ProviderRuntimeDescriptor",
    "ProviderRuntimeProtocol",
    "ProviderRuntimeRegistry",
    "ProviderScannerCapability",
    "ProviderScannerCatalog",
    "ProviderScopeType",
    "ReportProviderMetadata",
]


_EXPORTS: dict[str, tuple[str, str]] = {
    "ReportProviderMetadata": ("unio_collector.providers.report_metadata", "ReportProviderMetadata"),
}


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical application export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
