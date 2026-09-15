from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.scanners.scanner.definition import ScannerDefinition


@dataclass(frozen=True)
class ScannerDefinitionSource:
    """Named source of scanner definitions for deterministic discovery."""

    source_id: str
    definitions: Mapping[str, ScannerDefinition]
