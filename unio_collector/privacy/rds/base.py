"""Closed RDS identity and per-record controlled lifecycle roles."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.ec2.base import Ec2PrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

STATUS_CONTROLS = frozenset({"available", "stopped", "stopping", "unknown"})
TYPE_CONTROLS = frozenset({"manual", "automated", "awsbackup", "unknown"})


class RdsPrivacyContract(Ec2PrivacyContract):
    """Protect arbitrary provider strings while retaining finite analyzer controls."""

    def __init__(self, *, status_control: bool = False, type_control: bool = False, bound: bool = False) -> None:
        """Bind controlled literals to one already admitted record container."""
        self._bound = bound
        self._status_control = status_control
        self._type_control = type_control

    def for_container(self, value: dict[str, Any], path: str) -> RdsPrivacyContract | None:
        """Switch only the exact record, with typed finite lifecycle values."""
        if path == PREFIX + ".records[]" and not self._bound:
            return type(self)(
                bound=True,
                status_control=isinstance(value.get("status"), str) and value.get("status") in STATUS_CONTROLS,
                type_control=isinstance(value.get("snapshot_type"), str) and value.get("snapshot_type") in TYPE_CONTROLS,
            )
        return None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect unknown text and retain exact bound analyzer controls."""
        decision = super().resolve(path, profile)
        if decision is None:
            return None
        controlled = (path == PREFIX + ".records[].status" and self._status_control) or (path == PREFIX + ".records[].snapshot_type" and self._type_control)
        if controlled:
            return replace(
                decision, treatment="preserve", category="safe_metadata", reason="Finite producer/analyzer lifecycle control in the bound validated RDS record."
            )
        if decision.category == "free_text":
            return replace(decision, treatment="tokenise", reason="Arbitrary RDS provider text is protected as a whole string.")
        return decision

    def is_public_literal(self, suffix: str, value: object) -> bool:
        """Recognize only validated factual numbers and finite SDK/control roles."""
        if suffix == "records[].status":
            return self._status_control and isinstance(value, str) and value in STATUS_CONTROLS
        if suffix == "records[].snapshot_type":
            return self._type_control and isinstance(value, str) and value in TYPE_CONTROLS
        spec = self.fields.get(suffix)
        if spec is None or spec[1] != "safe_metadata" or value is None:
            return False
        kind = spec[0]
        allowed = {
            "count",
            "money",
            "version",
            "context",
            "reason",
            "digit",
            "parts_item",
            "namespace",
            "metric_name",
            "statistic",
            "interpretation",
            "metric_status",
            "snapshot_kind",
        }
        return kind in allowed and not isinstance(value, (dict, list)) and self._valid(value, kind, nullable=spec[2])

    def admitted_scan_record(self, value: object) -> bool:
        """Validate source or strict protected timestamps only in the scan-view context.

        Keep collection preflight strict. A read-only validation copy expands
        canonical month timestamps to their first day for DTO consistency; the
        scanned content, known originals and scanner return values stay intact.
        """

        def validation_copy(item: object, suffix: str) -> object:
            spec = self.fields.get(suffix)
            if spec is not None and spec[0] == "timestamp" and isinstance(item, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}", item):
                try:
                    return datetime.strptime(item, "%Y-%m").replace(tzinfo=UTC).isoformat()
                except ValueError:
                    return item
            if isinstance(item, dict):
                return {key: validation_copy(child, suffix + "." + key) for key, child in item.items()}
            if isinstance(item, list):
                return [validation_copy(child, suffix + "[]") for child in item]
            return item

        return not self.unknown_paths(validation_copy(value, "records[]"), "", "records[]")
