"""Scan-only view of declared strict financial and legacy-empty-list omissions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.flow.scan import FlowScanAdmission

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


class CommitmentScanAdmission:
    """Do not mutate raw evidence, archive bytes, findings or raw preflight admission."""

    @staticmethod
    def view(contract: ClosedProducerContract, value: Any, suffix: str) -> Any:  # noqa: ANN401
        """Recognize existing strict output only at independently declared exact field roles."""
        spec = contract.fields.get(suffix)
        if spec is not None:
            if spec[0] == "empty_array" and value is None:
                return []
            if spec[0] == "money" and spec[1] == "cost" and spec[2] and value == "":
                return None
        if isinstance(value, dict):
            return {key: CommitmentScanAdmission.view(contract, child, suffix + ("." if suffix else "") + key) for key, child in value.items()}
        if isinstance(value, list):
            return [CommitmentScanAdmission.view(contract, child, contract.sequence_item_path(suffix, index)) for index, child in enumerate(value)]
        return FlowScanAdmission.view(contract, value, suffix)
