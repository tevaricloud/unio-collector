from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.config.scan.detail.lower_precedence import (
        OverriddenLowerPrecedenceValue,
    )


@dataclass(frozen=True)
class ScanDetailOptionsResolution:
    """Resolved scanner options and explicit-profile displacement audit."""

    options: dict[str, dict[str, Any]]
    overridden_lower_precedence_values: tuple[
        OverriddenLowerPrecedenceValue,
        ...,
    ] = ()


__all__ = ["ScanDetailOptionsResolution"]
