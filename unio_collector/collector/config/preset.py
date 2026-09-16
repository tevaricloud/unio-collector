"""Neutral operational scan preset values."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CollectionPreset:
    """Operational defaults shared by standalone and application scans."""

    preset_id: str
    detail_profile: str | None = None
    regions_from_billing: bool | None = None
    allow_chargeable_scanners: bool | None = False
    scan_mode: str | None = None
    scan_pillars: tuple[str, ...] | None = None
