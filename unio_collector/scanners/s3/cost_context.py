from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws import errors as aws_errors
from unio_collector.scanners.cost_context import enrich_records_with_cost_context
from unio_collector.scanners.s3.storage_types import (
    S3_COST_EXPLORER_SERVICE_NAMES,
    TS3CostRecord,
)

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


def add_s3_cost_context(  # noqa: D103
    records: list[TS3CostRecord],
    context: ScannerContext,
) -> list[TS3CostRecord]:
    if not records:
        return records
    try:
        service_costs = context.costs.collect_service_costs()
        regional_costs = context.costs.collect_daily_costs(
            group_keys=("SERVICE", "REGION"),
        )
    except Exception as exc:  # noqa: BLE001
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        context.warnings.add(
            (f"S3 Cost Explorer context was unavailable; lifecycle metadata findings continued ({code})."),
        )
        return records
    return enrich_records_with_cost_context(
        records,
        service_names=S3_COST_EXPLORER_SERVICE_NAMES,
        service_costs=service_costs,
        daily_costs=regional_costs,
    )
