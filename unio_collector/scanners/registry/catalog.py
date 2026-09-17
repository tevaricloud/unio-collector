"""Canonical scanner discovery and lookup without application explanations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.scanners.registry.definitions import SCANNERS

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition


def get_scanner(scanner_id: str) -> ScannerDefinition:  # noqa: D103
    try:
        return SCANNERS[scanner_id]
    except KeyError as exc:
        msg = f"Unknown scanner ID: {scanner_id}"
        raise ValueError(msg) from exc


def list_scanners() -> list[ScannerDefinition]:  # noqa: D103
    return [SCANNERS[scanner_id] for scanner_id in sorted(SCANNERS)]


def validate_scanner_ids(scanner_ids: list[str] | tuple[str, ...] | set[str]) -> None:  # noqa: D103
    unknown = sorted(set(scanner_ids) - set(SCANNERS))
    if unknown:
        msg = f"Unknown scanner IDs: {', '.join(unknown)}"
        raise ValueError(msg)
