from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.providers.finding_source import FindingSource as Finding


class ScannerFindingGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner finding gateways."""

    @property
    def findings(self) -> list[Finding]: ...  # noqa: D102

    @findings.setter
    def findings(self, value: list[Finding]) -> None: ...
