from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class PrivacyPreviewOptions:
    """Inputs for an artifact-free privacy simulation."""

    bundle_path: Path
    profile_id: str = "standard"
    token_scope: str = "engagement"  # noqa: S105
    engagement_id: str = "default-engagement"
    client_id: str | None = None
    allow_unknown_fields: bool = False
    existing_vault_path: Path | None = None
    existing_recovery_key_path: Path | None = None
    passphrase: str | None = None
