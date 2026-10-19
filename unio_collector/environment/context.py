"""Privacy-safe serialized environment context."""

from typing import Literal

from pydantic import Field

from unio_collector.core.base_model import UnioBaseModel
from unio_collector.environment.types import (
    EnvironmentClassification,
    EnvironmentSubtype,
    EvidenceStrength,
)


class EnvironmentContext(UnioBaseModel):
    """Strict privacy-safe serialized environment context."""

    classifier_version: Literal["2026-09-gap-043-v1"]
    classification: EnvironmentClassification
    evidence_strength: EvidenceStrength
    canonical_subtype: EnvironmentSubtype | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
