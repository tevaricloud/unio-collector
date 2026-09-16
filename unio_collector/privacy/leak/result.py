from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.leak.finding import LeakFinding


@dataclass
class LeakScanResult:
    """Protected archive leak scan result."""

    files_scanned: int = 0
    findings: list[LeakFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return true when no leaks were detected."""
        return not self.findings

    def convert_to_dict(self) -> dict[str, object]:
        """Return JSON-safe scan summary."""
        return {
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "findings": [finding.convert_to_dict() for finding in self.findings],
        }
