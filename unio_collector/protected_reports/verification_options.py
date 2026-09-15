from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProtectedReportVerificationOptions:
    """Verification options for a trusted Tevari public key."""

    public_key_path: Path
    expected_key_id: str | None = None
