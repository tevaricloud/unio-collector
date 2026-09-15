from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

from unio_collector.scan_workflow.scanner.orchestration_contract import (
    ScannerScheduleRuntimeContract,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.evidence_gateway import (
        ScannerRunnerEvidenceGateway,
    )


class ScannerRunRuntimeContract(ScannerScheduleRuntimeContract, Protocol):
    """Runner fields required to prefetch shared evidence and schedule scanners."""

    @property
    def evidence_gateway(self) -> ScannerRunnerEvidenceGateway:
        """Return the scanner evidence gateway."""
        ...
