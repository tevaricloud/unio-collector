from __future__ import annotations

# ruff: noqa: D100
from typing import Literal

from unio_collector.core.base_model import UnioBaseModel


class OrganizationEnvelopeAccount(UnioBaseModel):
    """Reference an independently valid child account bundle."""

    account_reference: str
    bundle_path: str
    bundle_sha256: str
    status: Literal["completed", "degraded", "failed", "timed_out", "cancelled"]
    analysis_state: Literal["not_analyzed", "analyzed"]
    bundle_purpose: str | None = None
    bundle_schema_version: str | None = None
