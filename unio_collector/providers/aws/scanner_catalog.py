from __future__ import annotations  # noqa: D100

from unio_collector.providers.aws.adapter import AwsProviderAdapter
from unio_collector.providers.aws.identity import AWS_PROVIDER
from unio_collector.providers.scanner_catalog import ProviderScannerCatalog
from unio_collector.scanners.registry.catalog import list_scanners


class AwsProviderScannerCatalog:
    """Build AWS scanner catalog metadata from the existing registry."""

    def build(self) -> ProviderScannerCatalog:
        """Return provider-aware AWS scanner capability metadata."""
        adapter = AwsProviderAdapter()
        return ProviderScannerCatalog(
            provider_id=AWS_PROVIDER.provider_id,
            capabilities=tuple(adapter.build_scanner_capability(definition) for definition in list_scanners()),
            live_execution_supported=True,
        )
