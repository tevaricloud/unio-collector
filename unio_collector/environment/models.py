"""Typed environment-classification results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.environment.signal import EnvironmentSignal
    from unio_collector.environment.types import (
        EnvironmentClassification,
        EnvironmentSubtype,
        EvidenceStrength,
    )


@dataclass(frozen=True)
class EnvironmentResult:
    """Canonical environment result without raw matched customer text."""

    classification: EnvironmentClassification
    subtype: EnvironmentSubtype | None
    evidence_strength: EvidenceStrength
    signals: tuple[EnvironmentSignal, ...] = ()

    @property
    def custom_alias_applied(self) -> bool:
        """Return whether customer vocabulary influenced this result."""
        return any(signal.custom_alias for signal in self.signals)
