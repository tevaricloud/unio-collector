from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivacyTreatmentDecision:
    """Resolved non-secret privacy treatment for one structured value."""

    treatment: str
    category: str | None
    canonicaliser_id: str | None
    canonicaliser_version: str | None
    fallback_allowed: bool
    decision_source: str
    reason: str
