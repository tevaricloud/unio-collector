from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.evidence.runtime import ScannerEvidenceRuntime
    from unio_collector.scan_workflow.evidence_collection import (
        ScannerEvidenceCollectionService,
    )
    from unio_collector.scan_workflow.runner.evidence_gateway import (
        ScannerRunnerEvidenceGateway,
    )


@dataclass
class ScannerRunnerEvidenceState:
    """Evidence runtime collaborators and shared prefetch records."""

    evidence_runtime: ScannerEvidenceRuntime
    collection_service: ScannerEvidenceCollectionService
    evidence_gateway: ScannerRunnerEvidenceGateway
    shared_evidence_prefetches: list[dict[str, Any]] = field(default_factory=list)
