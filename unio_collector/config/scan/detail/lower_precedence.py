from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class OverriddenLowerPrecedenceValue:
    """One supplied scanner YAML value displaced by an explicit profile."""

    scanner_id: str
    option_name: str
    previous_source: str
    previous_value: object
    effective_source: str
    effective_value: object

    @property
    def option_key(self) -> str:
        """Return the canonical scanner-option key."""
        return f"{self.scanner_id}.{self.option_name}"

    def convert_to_dict(self) -> dict[str, object]:
        """Return a manifest-safe representation."""
        return {
            "scanner_id": self.scanner_id,
            "option_name": self.option_name,
            "previous_source": self.previous_source,
            "previous_value": self.previous_value,
            "effective_source": self.effective_source,
            "effective_value": self.effective_value,
        }


__all__ = ["OverriddenLowerPrecedenceValue"]
