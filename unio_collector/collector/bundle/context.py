from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.scan_period import serialize_scan_period

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class CollectorBundleContext:
    """Findings-empty canonical bundle context for collection-only output."""

    generated_at: datetime
    account_context: dict[str, Any]
    scan_period: object
    findings: list[object] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        """Return the canonical report-bundle-compatible JSON shape."""
        del mode
        return {
            "generated_at": self.generated_at.isoformat(),
            "account_context": self.account_context,
            "scan_period": serialize_scan_period(self.scan_period),
            "findings": [],
            "summary": {
                **self.summary,
                "authoritative_for_analysis": False,
                "analysis_state": "not_analyzed",
                "compatibility_role": "collection_context_only",
            },
        }

    def model_copy(self, *, update: dict[str, Any]) -> CollectorBundleContext:
        """Provide the narrow Pydantic-compatible copy seam used by the writer."""
        return replace(self, **update)
