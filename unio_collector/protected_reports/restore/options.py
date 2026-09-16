from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class ProtectedReportRestoreOptions:
    """Options for local protected report restoration."""

    package_path: Path
    vault_path: Path
    output_dir: Path
    passphrase: str | None = None
    recovery_key_path: Path | None = None
    tevari_public_key_path: Path | None = None
    expected_key_id: str | None = None
    allow_unsigned: bool = False
    overwrite: bool = False
    warning_details: tuple[SecurityWarning, ...] = ()
