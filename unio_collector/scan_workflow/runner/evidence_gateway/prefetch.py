from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        SharedEvidencePrefetchSource,
    )


class SharedEvidencePrefetchGateway:
    """Delegate shared evidence prefetching to the collection source."""

    def __init__(self, source: SharedEvidencePrefetchSource) -> None:  # noqa: D107
        self._source = source

    def prefetch_shared_evidence(
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        """Prefetch shared evidence needed by the selected scanner set."""
        self._source.prefetch_shared_evidence(scanner_ids)
