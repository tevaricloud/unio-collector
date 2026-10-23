"""Validate exact strict redactions in a scan-only copy, never raw admission."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract

MONTH_LENGTH = 7


class EdgeScanAdmission:
    """Preserve unknown/type guards while recognizing existing strict-profile output."""

    @staticmethod
    def record(value: object) -> object:
        """Only the exact strict-removed pricing-class list can become an empty scan list."""
        if isinstance(value, dict) and "sample_price_classes" in value and value["sample_price_classes"] is None:
            return dict(value, sample_price_classes=[])
        return value

    @staticmethod
    def check(contract: ClosedProducerContract, value: object, suffix: str) -> bool:
        """Do not change the source/archive or admit unknown siblings and invalid timestamps."""
        checked: Any = value
        if "records[].sample_price_classes" in contract.fields:
            if suffix == "records[]":
                checked = EdgeScanAdmission.record(value)
            elif suffix == "records" and isinstance(value, list):
                checked = [EdgeScanAdmission.record(row) for row in value]
            elif suffix == "" and isinstance(value, dict) and isinstance(value.get("records"), list):
                checked = dict(value, records=[EdgeScanAdmission.record(row) for row in value["records"]])
        if suffix == "" and isinstance(checked, dict):
            checked = dict(checked)
            stamp = checked.get("collection_time")
            if isinstance(stamp, str) and len(stamp) == MONTH_LENGTH:
                try:
                    datetime.fromisoformat(stamp + "-01")
                except ValueError:
                    return False
                checked["collection_time"] = stamp + "-01"
        return not contract.unknown_paths(checked, "", suffix)
