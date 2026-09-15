from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class VaultRekeyOptions:
    """Inputs for wrapping-key rotation without token-key rotation."""

    vault_path: Path
    output_vault_path: Path
    old_passphrase: str | None
    old_recovery_key_path: Path | None
    new_recovery_mode: str
    new_passphrase: str | None
    new_recovery_key_path: Path | None
    in_place: bool = False
    overwrite: bool = False
