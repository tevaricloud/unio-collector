from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerOptionOverride:  # noqa: D101
    scanner_id: str
    option_name: str
    value: object
