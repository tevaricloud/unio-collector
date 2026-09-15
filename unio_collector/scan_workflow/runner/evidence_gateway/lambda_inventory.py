from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        LambdaInventoryEvidenceSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class LambdaInventoryEvidenceGateway:
    """Delegate Lambda function inventory collection to the Lambda source."""

    def __init__(self, source: LambdaInventoryEvidenceSource) -> None:  # noqa: D107
        self._source = source

    def collect_cached_lambda_function_inventory(
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        """Return cached Lambda function inventory grouped by region."""
        return self._source.collect_cached_lambda_function_inventory(definition)
