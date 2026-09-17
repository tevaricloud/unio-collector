from __future__ import annotations  # noqa: D100

import os
from dataclasses import dataclass
from pathlib import Path

from unio_collector.config.constants import (
    DEFAULT_CONFIG_FILE_NAME,
    DISABLE_DEFAULT_CONFIG_ENV,
)


@dataclass(frozen=True)
class DefaultConfigResolver:
    """Resolve the optional default YAML config file path."""

    root: Path | None = None

    def get_default_config_path(self) -> Path:  # noqa: D102
        return (self.root or Path.cwd()) / DEFAULT_CONFIG_FILE_NAME

    def resolve_config_path(self, explicit_config: str | None) -> Path | None:  # noqa: D102
        if explicit_config:
            return Path(explicit_config)
        if self.detect_default_config_disabled():
            return None
        default_path = self.get_default_config_path()
        if default_path.exists():
            return default_path
        return None

    def detect_missing_default_config(self) -> bool:  # noqa: D102
        if self.detect_default_config_disabled():
            return False
        return not self.get_default_config_path().exists()

    def build_missing_default_warning(self) -> str:  # noqa: D102
        path = self.get_default_config_path()
        return (
            f"No default {DEFAULT_CONFIG_FILE_NAME} was found at {path}. "
            "Unio Collector will continue with built-in defaults unless --config points "
            "to another YAML file."
        )

    def detect_default_config_disabled(self) -> bool:  # noqa: D102
        return os.getenv(DISABLE_DEFAULT_CONFIG_ENV, "").lower() in {
            "1",
            "true",
            "yes",
        }
