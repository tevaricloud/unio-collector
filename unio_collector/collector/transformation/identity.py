from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.collector.execution.result import CollectorExecutionResult


class IdentityEvidenceTransformationPolicy:
    """Preserve collected artifacts unchanged."""

    def transform(
        self,
        result: CollectorExecutionResult,
    ) -> CollectorExecutionResult:
        """Return the original collection result."""
        return result
