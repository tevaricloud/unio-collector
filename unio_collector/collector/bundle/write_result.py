from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class BundleWriteResult:
    """Filesystem path and manifest produced by evidence-bundle writing."""

    path: Path
    manifest: dict[str, Any]
