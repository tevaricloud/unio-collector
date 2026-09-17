from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerCliOverride:
    """One recognized scanner-specific CLI override and its provenance."""

    scanner_id: str
    option_name: str
    cli_option: str
    value: object

    @property
    def option_key(self) -> str:
        """Return the canonical scanner-option key."""
        return f"{self.scanner_id}.{self.option_name}"

    def convert_to_dict(self) -> dict[str, object]:
        """Return a manifest-safe representation."""
        return {
            "scanner_id": self.scanner_id,
            "option_name": self.option_name,
            "cli_option": self.cli_option,
            "effective_value": self.value,
        }


__all__ = ["ScannerCliOverride"]
