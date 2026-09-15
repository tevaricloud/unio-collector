from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigKeySpec:
    """Reference metadata for one YAML config key or namespace."""

    key: str
    description: str
    value_type: str = "value"
    default: str | None = None
    allowed_values: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    deprecation_note: str = ""
    dynamic: bool = False
    dynamic_reason: str = ""

    def convert_to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-ready representation."""
        return {
            "aliases": list(self.aliases),
            "allowed_values": list(self.allowed_values),
            "default": self.default,
            "deprecated": bool(self.deprecation_note),
            "deprecation_note": self.deprecation_note,
            "description": self.description,
            "dynamic": self.dynamic,
            "dynamic_reason": self.dynamic_reason,
            "key": self.key,
            "type": self.value_type,
        }
