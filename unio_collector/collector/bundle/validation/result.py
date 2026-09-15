from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class BundleValidationResult:  # noqa: D101
    path: Path
    passed: bool
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "path": str(self.path),
            "passed": self.passed,
            "errors": list(self.errors),
        }
