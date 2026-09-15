from __future__ import annotations  # noqa: D100

from typing import Protocol


class SharedEvidencePrefetchSource(Protocol):
    """Evidence source capable of prefetching shared scanner evidence."""

    def prefetch_shared_evidence(
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        """Prefetch shared evidence needed by the selected scanner set."""
        ...
