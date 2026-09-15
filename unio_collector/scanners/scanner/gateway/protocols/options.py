from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView


class ScannerOptionsGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner options gateways."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102
