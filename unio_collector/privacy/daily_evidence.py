"""Closed privacy treatment for the two existing daily-cost evidence producers."""

from __future__ import annotations

from datetime import date
from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "records[].date": ("date", "timestamp", False),
    "records[].service_name": ("string", "free_text", False),
    "records[].region": ("string", "region", False),
    "records[].usage_type": ("string", "free_text", True),
    "records[].cost": ("money", "cost", False),
    "records[].currency": ("string", "cost", False),
    "regions": ("array", "safe_metadata", False),
    "regions[]": ("string", "region", False),
    "scan_period": ("object", "safe_metadata", True),
    "scan_period.kind": ("period_kind", "safe_metadata", False),
    "scan_period.raw_input": ("object", "safe_metadata", False),
    **{f"scan_period.{key}": ("date", "timestamp", False) for key in ("current_start_date", "current_end_date", "previous_start_date", "previous_end_date")},
    **{f"scan_period.raw_input.{key}": ("date", "timestamp", False) for key in ("date_from", "date_to")},
    **{f"scan_period.raw_input.{key}": ("duration", "safe_metadata", False) for key in ("days", "months", "years")},
}


class DailyEvidencePrivacyContract(ClosedProducerContract):
    """Recognize exact legacy AWS daily evidence without admitting other scanners."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind the finite policy to its existing source and scanner identities."""
        if record.get("scanner_id") not in {"cost-spike-analysis", "data-transfer-cost-review"}:
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.scanners.cost_explorer.daily_evidence", "DailyCostEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Daily-cost privacy contract requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "period_kind":
            return isinstance(value, str) and value in {"days", "months", "years", "date_range"}
        if kind == "duration":
            return type(value) is int and value > 0
        if kind == "date":
            if not isinstance(value, str):
                return False
            try:
                return date.fromisoformat(value).isoformat() == value
            except ValueError:
                return False
        return super()._valid(value, kind, nullable=nullable)
