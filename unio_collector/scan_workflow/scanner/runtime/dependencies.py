from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scanners.scanner.definition import ScannerDefinition

type ScannerFactory[ScannerT] = Callable[[str, ScannerDefinition], ScannerT]


@dataclass(frozen=True)
class ScannerRuntimeDependencies[ScannerT]:
    """Dependencies used while running scanner implementations."""

    scanner_factory: ScannerFactory[ScannerT]
    progress: Callable[[ScanProgressEvent], None] | None
    scanner_total: int | None
