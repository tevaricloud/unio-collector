from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.scanners.scanner.option_override import ScannerOptionOverride


@dataclass(frozen=True)
class ScanDetailOptionContract:
    """Paired coverage values for one scan-detail-owned scanner option."""

    scanner_id: str
    option_name: str
    development_value: object
    full_value: object
    full_value_is_authoritative: bool = True
    full_value_requires_explicit_selection: bool = False
    allowed_values: frozenset[object] | None = None

    def build_override(self, value: object) -> ScannerOptionOverride:
        """Build a scanner override for one value from this contract."""
        return ScannerOptionOverride(
            scanner_id=self.scanner_id,
            option_name=self.option_name,
            value=value,
        )
