from __future__ import annotations  # noqa: D100

from typing import Protocol

from unio_collector.scan_workflow.runner.evidence_gateway.protocols.cloudwatch import (
    CloudWatchEvidenceSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.cost import (
    CostEvidenceSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.lambda_inventory import (
    LambdaInventoryEvidenceSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.notes import (
    EvidenceNoteSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.prefetch import (
    SharedEvidencePrefetchSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.regional import (
    RegionalInventoryEvidenceSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.s3 import (
    S3EvidenceSource,
)
from unio_collector.scan_workflow.runner.evidence_gateway.protocols.tagging import (
    ResourceTaggingEvidenceSource,
)


class ScannerEvidenceCollectionGatewaySource(
    SharedEvidencePrefetchSource,
    CostEvidenceSource,
    RegionalInventoryEvidenceSource,
    ResourceTaggingEvidenceSource,
    CloudWatchEvidenceSource,
    S3EvidenceSource,
    LambdaInventoryEvidenceSource,
    EvidenceNoteSource,
    Protocol,
):
    """Full structural source accepted by the compatibility gateway."""
