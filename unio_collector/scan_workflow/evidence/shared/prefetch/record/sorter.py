from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SharedEvidencePrefetchRecordSorter:
    """Sorts shared-evidence records into deterministic scheduler order."""

    namespace_order: dict[str, int] | None = None

    def sort_records(self, records: list[dict[str, Any]]) -> None:  # noqa: D102
        namespace_order = self.namespace_order or {
            "s3_bucket_index": 0,
            "cost_explorer_daily_costs": 1,
        }
        records.sort(
            key=lambda item: (
                namespace_order.get(str(item.get("namespace") or ""), 99),
                tuple(item.get("group_keys") or ()),
                str(item.get("consumer_id") or ""),
                str(item.get("status") or ""),
            ),
        )
