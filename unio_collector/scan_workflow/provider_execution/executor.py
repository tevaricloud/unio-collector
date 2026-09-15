from __future__ import annotations  # noqa: D100

from typing import Protocol


class ProviderScanExecutorProtocol[ResultT](Protocol):
    """Provider-owned scan execution boundary."""

    def execute(
        self,
        config: object,
        selection: object,
        progress: object | None = None,
    ) -> ResultT:
        """Run provider-owned scan execution and return report pipeline input."""
        ...
