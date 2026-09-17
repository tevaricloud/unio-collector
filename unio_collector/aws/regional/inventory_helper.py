from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.collection import RegionalAwsCollectionRunner

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext

InventoryRecordT = TypeVar("InventoryRecordT")


@dataclass(frozen=True)
class RegionalInventoryCollectionHelper:
    """Run regional AWS inventory collection for collector facade methods."""

    session: Any
    account_id: str | None
    audit_context: AwsAuditContext
    collector_id: str

    def collect_region_records(  # noqa: D102
        self,
        *,
        regions: list[str],
        service: str,
        operation: str,
        collect_region: Callable[[str], list[InventoryRecordT]],
    ) -> list[InventoryRecordT]:
        result = RegionalAwsCollectionRunner(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id=self.collector_id,
        ).collect_region_lists(
            regions=regions,
            service=service,
            operation=operation,
            collect_region=collect_region,
        )
        return result.values
