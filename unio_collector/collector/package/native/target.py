from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class NativeCollectorTarget:
    """One supported native release target."""

    operating_system: str
    architecture: str
    portable_format: str
    installer_format: str


__all__ = ["NativeCollectorTarget"]
