from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class LambdaInventoryEvidenceSource(Protocol):
    """Lambda inventory evidence methods required by scanners."""

    def collect_cached_lambda_function_inventory(
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        """Return cached Lambda function inventory grouped by region."""
        ...
