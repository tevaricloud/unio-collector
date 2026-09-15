from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.lambda_cost.cycle.inventory.collector import (
    LambdaCostCycleInventoryCollector,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from unio_collector.aws.lambda_cost.function.inventory import (
        LambdaFunctionInventoryRecord,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class LambdaInventoryEvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def collect_cached_lambda_function_inventory(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="lambda_function_inventory",
            label="Lambda function inventory",
        )
        runtime_state = self.runner.runtime_state
        selected_regions = runtime_state.get_selected_regions()
        collector = LambdaCostCycleInventoryCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=self.runner.create_audit_context(
                definition,
                "LambdaFunctionInventoryCollector",
            ),
            selected_regions=selected_regions,
        )
        regions = collector.get_available_regions()
        access = runtime_state.cache.get_or_load_with_status(
            "lambda_function_inventory",
            (
                runtime_state.account_id,
                tuple(regions),
            ),
            lambda: collector.collect_function_inventory_by_region(regions=regions),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="lambda_function_inventory",
            label="Lambda function inventory",
            access_status=access.status,
        )
        return {region: list(records) for region, records in access.value.items()}
