from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class UnlockedVault:
    """Authenticated vault content and its recovered root key."""

    payload: dict[str, object]
    metadata: dict[str, object]
    plaintext: dict[str, object]
    root_key: bytes
