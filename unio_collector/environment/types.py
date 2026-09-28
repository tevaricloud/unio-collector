"""Shared environment-classification type aliases."""

from typing import Literal

CLASSIFIER_VERSION = "2026-09-gap-043-v1"

EnvironmentClassification = Literal[
    "production",
    "non-production",
    "unknown",
    "conflicting",
]
EnvironmentSubtype = Literal[
    "production",
    "development",
    "staging",
    "test",
    "non-production",
]
EvidenceStrength = Literal["high", "medium", "low", "unknown"]
