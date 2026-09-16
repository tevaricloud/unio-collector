"""Read encrypted vault content and lineage from the same admitted bytes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.encoding import load_json_object

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class VaultSource:
    """An encrypted vault snapshot and its exact content identity."""

    payload: dict[str, Any]
    sha256: str

    @classmethod
    def read(cls, path: Path) -> VaultSource:
        """Admit one read without rereading its path for lineage."""
        try:
            content = path.read_bytes()
            payload = load_json_object(content.decode("utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            message = "Encrypted vault could not be read as an unambiguous JSON object."
            raise ValueError(message) from exc
        return cls(payload=payload, sha256=hashlib.sha256(content).hexdigest())
