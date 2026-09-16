from __future__ import annotations  # noqa: D100

from enum import StrEnum


class ScanDetailProfileSource(StrEnum):
    """Source that selected the effective scan-detail profile."""

    EXPLICIT_CLI = "explicit_cli"
    CONFIG = "config"
    PRESET = "preset"
    DEFAULT = "default"


__all__ = ["ScanDetailProfileSource"]
