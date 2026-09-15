from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


def get_selected_or_available_regions(  # noqa: D103
    context: ScannerContext,
    service_name: str,
) -> list[str]:
    selected = context.options.get_selected_regions()
    regions = [region for region in selected if region != "global"] if selected else context.security.session.get_available_regions(service_name)
    return regions or ["us-east-1"]
