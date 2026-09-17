from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class VaultRekeyResult:
    """Published vault rekey artifacts."""

    vault_path: Path
    recovery_key_path: Path | None
