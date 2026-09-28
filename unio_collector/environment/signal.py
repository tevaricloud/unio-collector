"""Non-identifying environment-classification signals."""

from dataclasses import dataclass
from typing import Literal

from unio_collector.environment.types import EnvironmentSubtype, EvidenceStrength


@dataclass(frozen=True)
class EnvironmentSignal:
    """One non-identifying environment signal."""

    classification: Literal["production", "non-production"]
    subtype: EnvironmentSubtype
    evidence_strength: EvidenceStrength
    source: str
    custom_alias: bool = False
