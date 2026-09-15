from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProtectedReportPackageValidationResult:
    """Validation result for an unsigned protected report-package payload."""

    passed: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
