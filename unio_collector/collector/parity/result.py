from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.collector.parity.exception import AwsCollectionParityException


@dataclass(frozen=True)
class AwsCollectionParityResult:
    """Normalized result of comparing core and collector capability models."""

    status: str
    differences: tuple[dict[str, Any], ...]
    applied_exceptions: tuple[AwsCollectionParityException, ...]
    exception_errors: tuple[str, ...]
    core_semantic_sha256: str
    collector_semantic_sha256: str

    @property
    def passed(self) -> bool:
        """Return whether all dimensions match or have valid exact exceptions."""
        return self.status == "passed"

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic machine-readable comparison evidence."""
        return {
            "status": self.status,
            "core_semantic_sha256": self.core_semantic_sha256,
            "collector_semantic_sha256": self.collector_semantic_sha256,
            "differences": [dict(item) for item in self.differences],
            "applied_exceptions": [item.convert_to_dict() for item in self.applied_exceptions],
            "exception_errors": list(self.exception_errors),
        }


__all__ = ["AwsCollectionParityResult"]
