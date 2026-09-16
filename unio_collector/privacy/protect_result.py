from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class PrivacyProtectResult:
    """Summary of a protected bundle write."""

    output_path: Path
    vault_path: Path
    recovery_key_path: Path | None
    preview_output_path: Path | None
    receipt_path: Path
    preview: dict[str, object]
    warnings: tuple[str, ...] = ()
    warning_details: tuple[SecurityWarning, ...] = ()
