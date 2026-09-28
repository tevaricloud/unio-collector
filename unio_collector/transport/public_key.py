"""Dedicated RSA recipient public-key loading and validation."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from unio_collector.transport.constants import RSA_MINIMUM_BITS

if TYPE_CHECKING:
    from pathlib import Path


def load_public_key(path: Path) -> RSAPublicKey:
    """Load a dedicated recipient encryption public key."""
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError("Recipient transport public key could not be loaded.") from exc
    if not isinstance(key, RSAPublicKey) or key.key_size < RSA_MINIMUM_BITS:
        raise ValueError("Recipient transport public key must be RSA with at least 2048 bits.")
    return key


__all__ = ["load_public_key"]
