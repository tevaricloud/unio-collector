"""Collector-safe evidence transformation policies."""

from __future__ import annotations

from unio_collector.collector.transformation.identity import (
    IdentityEvidenceTransformationPolicy,
)
from unio_collector.collector.transformation.policy import EvidenceTransformationPolicy

__all__ = [
    "EvidenceTransformationPolicy",
    "IdentityEvidenceTransformationPolicy",
]
