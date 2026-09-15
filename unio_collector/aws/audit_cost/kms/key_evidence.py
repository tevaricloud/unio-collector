"""Normalized KMS key evidence for deterministic analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

type KmsTagReadState = Literal["known_tagged", "known_untagged", "unknown"]


@dataclass(frozen=True)
class KmsKeyEvidence:
    """Allowlisted provider facts for one visible KMS key."""

    key_id: str
    key_manager: str = ""
    key_state: str = ""
    key_spec: str = ""
    key_usage: str = ""
    origin: str = ""
    multi_region: bool = False
    multi_region_key_type: str = ""
    rotation_applicable: bool = False
    rotation_enabled: bool | None = None
    tag_read_state: KmsTagReadState = "unknown"
    tag_count: int | None = None


__all__ = ["KmsKeyEvidence", "KmsTagReadState"]
