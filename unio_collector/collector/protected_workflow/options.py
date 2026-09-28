"""Typed inputs for integrated protected collection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class ProtectedCollectionOptions:
    """Inputs for one integrated collection and privacy-protection run."""

    protected_bundle_path: Path
    vault_path: Path
    recovery_key_path: Path | None = None
    receipt_path: Path | None = None
    retain_raw_bundle_path: Path | None = None
    temporary_directory: Path | None = None
    recovery_mode: str = "passphrase"
    passphrase: str | None = None
    privacy_profile: str = "standard"
    token_scope: str = "engagement"  # noqa: S105
    engagement_id: str = "default-engagement"
    client_id: str | None = None
    existing_vault_path: Path | None = None
    existing_recovery_key_path: Path | None = None
    allow_unknown_fields: bool = False
    acknowledge_vault_loss_risk: bool = False
    overwrite: bool = False
    warning_details: tuple[SecurityWarning, ...] = ()
    progress: Callable[[str, str], None] | None = None
    environment_alias_file: Path | None = None
    environment_semantics: str | None = None
