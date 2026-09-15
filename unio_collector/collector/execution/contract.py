from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.collector.execution.result import CollectorExecutionResult


class ProviderCollectionExecutorProtocol(Protocol):
    """Provider-owned read-only collection boundary."""

    def execute_collection(
        self,
        config: object,
        selection: object,
        progress: object | None = None,
    ) -> CollectorExecutionResult:
        """Collect evidence without evaluating findings."""
        ...
