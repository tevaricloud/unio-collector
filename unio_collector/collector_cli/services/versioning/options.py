from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class VersionCheckOptions:
    """Trusted inputs for one explicit release metadata check."""

    metadata_location: str
    signature_location: str
    public_key_path: str


__all__ = ["VersionCheckOptions"]
