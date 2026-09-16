from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.collector.execution.result import CollectorExecutionResult


class EvidenceTransformationPolicy(Protocol):
    """Transform collector artifacts before bundle serialization."""

    def transform(
        self,
        result: CollectorExecutionResult,
    ) -> CollectorExecutionResult:
        """Return transformed collector output without evaluating findings."""
        ...
