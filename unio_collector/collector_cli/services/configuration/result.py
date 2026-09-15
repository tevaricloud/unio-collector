from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector_cli.services.configuration.data import (
        CollectorFileConfig,
    )
    from unio_collector.scanners.scanner.selection import ScannerSelection


@dataclass(frozen=True)
class CollectorConfigResult:
    """Resolved collector configuration and scanner selection."""

    config: CollectionConfigProtocol
    selection: ScannerSelection
    file_config: CollectorFileConfig


__all__ = ["CollectorConfigResult"]
