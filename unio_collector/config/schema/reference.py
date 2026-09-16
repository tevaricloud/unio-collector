from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.config.schema.key_spec import ConfigKeySpec


@dataclass(frozen=True)
class ConfigReference:
    """Deterministic config reference generated from key specs."""

    specs: tuple[ConfigKeySpec, ...]
    aliases: dict[str, str] = field(default_factory=dict)

    def get(self, key: str) -> ConfigKeySpec | None:
        """Return a spec by canonical key or alias."""
        canonical = self.aliases.get(key, key)
        for spec in self.specs:
            if spec.key == canonical:
                return spec
        return None

    def convert_to_dict(self) -> dict[str, object]:
        """Return deterministic schema/reference data."""
        return {
            "schema_version": 1,
            "keys": [spec.convert_to_dict() for spec in self.specs],
        }
