from __future__ import annotations  # noqa: D100

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def sha256_file(path: Path) -> str:
    """Return a stable prefixed SHA-256 digest for one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def sha256_bytes(data: bytes) -> str:
    """Return a stable prefixed SHA-256 digest for bytes."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
