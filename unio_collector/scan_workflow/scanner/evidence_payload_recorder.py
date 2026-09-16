from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.payload_storage_target import (
        ScannerEvidencePayloadRecorderTarget,
    )


class ScannerEvidencePayloadRecorder:
    """Record serialized scanner evidence payloads on runtime state."""

    def __init__(self, runtime: ScannerEvidencePayloadRecorderTarget) -> None:  # noqa: D107
        self._runtime = runtime

    def record_scanner_evidence_payload(
        self,
        scanner_id: str,
        payload: dict[str, Any],
    ) -> None:
        """Record a scanner evidence payload with its scanner identifier."""
        self._runtime.output_state.scanner_evidence_payloads.append(
            {
                "scanner_id": scanner_id,
                **payload,
            },
        )
