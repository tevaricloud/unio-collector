"""Normalized Secrets Manager metadata for deterministic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from datetime import datetime

type SecretTagReadState = Literal["known_tagged", "known_untagged"]


@dataclass(frozen=True)
class SecretEvidence:
    """Allowlisted provider metadata for one secret without its value."""

    name: str
    scheduled_deletion: bool = False
    rotation_enabled: bool = False
    last_accessed_at: datetime | None = None
    replica_regions: list[str] = field(default_factory=list)
    kms_key_id: str | None = None
    owning_service: str | None = None
    rotation_lambda_configured: bool = False
    tag_read_state: SecretTagReadState = "known_untagged"
    tag_count: int = 0


__all__ = ["SecretEvidence", "SecretTagReadState"]
