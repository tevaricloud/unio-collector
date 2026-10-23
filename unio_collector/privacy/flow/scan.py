"""Scan-only typed handling of strict month precision and removed route context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract

MONTH_LENGTH = 7


class FlowScanAdmission:
    """Never alter archives, findings or raw contract admission."""

    @staticmethod
    def view(contract: ClosedProducerContract, value: Any, suffix: str) -> Any:  # noqa: ANN401
        """Copy only exact declared timestamp/nullable-association redactions."""
        spec = contract.fields.get(suffix)
        if isinstance(value, str) and spec is not None:
            if spec[1] == "timestamp" and len(value) == MONTH_LENGTH:
                return value + "-01"
            if spec[0] == "association" and spec[2] and value == "":
                return None
        if isinstance(value, dict):
            return {key: FlowScanAdmission.view(contract, child, suffix + ("." if suffix else "") + key) for key, child in value.items()}
        if isinstance(value, list):
            return [FlowScanAdmission.view(contract, child, contract.sequence_item_path(suffix, index)) for index, child in enumerate(value)]
        return value
