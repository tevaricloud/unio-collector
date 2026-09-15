from __future__ import annotations  # noqa: D100

from typing import Any, Protocol


class ScannerWarningGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner warning gateways."""

    def add_scanner_warning(self, scanner_id: str, warning: str) -> None: ...  # noqa: D102

    def add_scanner_coverage_note(  # noqa: D102
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None: ...
