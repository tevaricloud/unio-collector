from __future__ import annotations  # noqa: D100

from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase


class SecurityEvidenceMixin(EvidenceCollectionBase):
    """Reserved boundary for shared security evidence collection.

    Security-governance scanners currently use scanner-specific collectors.
    This mixin keeps the Phase 10 domain boundary explicit without changing
    AWS calls or scanner-facing runtime methods.
    """
