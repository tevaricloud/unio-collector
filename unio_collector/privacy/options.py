from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class PrivacyProtectOptions:
    """Options for protected bundle creation."""

    bundle_path: Path
    output_path: Path
    vault_path: Path
    recovery_key_path: Path | None = None
    preview_output_path: Path | None = None
    receipt_path: Path | None = None
    recovery_mode: str = "passphrase"
    passphrase: str | None = None
    profile_id: str = "standard"
    token_scope: str = "engagement"  # noqa: S105
    engagement_id: str = "default-engagement"
    overwrite: bool = False
    allow_unknown_fields: bool = False
    acknowledge_vault_loss_risk: bool = False
    warning_details: tuple[SecurityWarning, ...] = ()
    existing_vault_path: Path | None = None
    existing_recovery_key_path: Path | None = None
    client_id: str | None = None
    in_place_vault_update: bool = False
