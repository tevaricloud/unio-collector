from __future__ import annotations  # noqa: D100

import hashlib
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    """Return a stable fingerprint for public-key pinning."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()
