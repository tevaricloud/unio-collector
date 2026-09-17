from __future__ import annotations  # noqa: D100

from typing import Any, Protocol


class ScannerDataGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner data gateways."""

    @property
    def scanner_data(self) -> dict[str, Any]: ...  # noqa: D102

    @scanner_data.setter
    def scanner_data(self, value: dict[str, Any]) -> None: ...
