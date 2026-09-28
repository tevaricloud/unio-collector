from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AwsOperationCapability:
    """One AWS operation derived from scanner and IAM metadata."""

    service: str
    operation: str
    requirement_types: tuple[str, ...]
    conditional: bool
    chargeable: bool

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-compatible operation metadata."""
        return asdict(self)


__all__ = ["AwsOperationCapability"]
