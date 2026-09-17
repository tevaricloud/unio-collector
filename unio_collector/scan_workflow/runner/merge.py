from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.scan_workflow.runner.merge_contract import (
        ScannerChildMergeRuntimeContract,
    )


class ScannerChildRunnerMergeService:
    """Merge isolated scanner runner output into the parent scan runner."""

    def __init__(self, parent_runner: ScannerChildMergeRuntimeContract) -> None:  # noqa: D107
        self.parent_runner = parent_runner

    def merge_child_runner(
        self,
        child_runner: ScannerChildMergeRuntimeContract,
    ) -> None:
        """Merge findings, results, evidence, warnings, and scan data."""
        parent_output = self.parent_runner.output_state
        child_output = child_runner.output_state
        parent_notes = self.parent_runner.note_state
        child_notes = child_runner.note_state
        snapshot = child_output.timeout_merge_snapshot
        if snapshot is not None:
            self._merge_snapshot(snapshot)
            return
        parent_output.findings.extend(child_output.findings)
        parent_output.results.extend(child_output.results)
        parent_output.service_deltas.extend(
            self._get_new_service_deltas(child_runner),
        )
        parent_output.scanner_evidence_payloads.extend(
            child_output.scanner_evidence_payloads,
        )
        parent_output.evidence_store.extend(
            child_output.evidence_store.get_records(),
        )
        self._merge_scanner_data(child_output.scanner_data)
        self._merge_mapping_lists(
            parent_notes.scanner_warnings,
            child_notes.scanner_warnings,
        )
        self._merge_mapping_lists(
            parent_notes.scanner_coverage_notes,
            child_notes.scanner_coverage_notes,
        )

    def _merge_scanner_data(self, child_data: Mapping[str, Any]) -> None:
        parent_data = self.parent_runner.output_state.scanner_data
        for key, child_value in child_data.items():
            if key not in parent_data:
                parent_data[key] = child_value
                continue
            parent_data[key] = self._merge_value(
                parent_data[key],
                child_value,
            )

    def _merge_value(self, parent_value: Any, child_value: Any) -> Any:  # noqa: ANN401
        if isinstance(parent_value, dict) and isinstance(child_value, dict):
            return self._merge_dict_values(parent_value, child_value)
        if isinstance(parent_value, list) and isinstance(child_value, list):
            return [*parent_value, *child_value]
        if parent_value == child_value:
            return parent_value
        return {
            "merge_conflict": True,
            "parent_value": parent_value,
            "child_value": child_value,
        }

    def _merge_dict_values(
        self,
        parent_value: dict[str, Any],
        child_value: dict[str, Any],
    ) -> dict[str, Any]:
        merged = dict(parent_value)
        for key, value in child_value.items():
            if key not in merged:
                merged[key] = value
                continue
            merged[key] = self._merge_value(merged[key], value)
        return merged

    def _merge_mapping_lists(
        self,
        parent_mapping: dict[str, list[Any]],
        child_mapping: Mapping[str, list[Any]],
    ) -> None:
        for key, values in child_mapping.items():
            parent_mapping.setdefault(key, []).extend(values)

    def _get_new_service_deltas(
        self,
        child_runner: ScannerChildMergeRuntimeContract,
    ) -> list[ServiceSpendDelta]:
        inherited_count = child_runner.output_state.inherited_service_delta_count
        try:
            start_index = int(inherited_count)
        except (TypeError, ValueError):
            start_index = 0
        return list(child_runner.output_state.service_deltas[start_index:])

    def _merge_snapshot(self, snapshot: Any) -> None:  # noqa: ANN401
        parent_output = self.parent_runner.output_state
        parent_notes = self.parent_runner.note_state
        parent_output.findings.extend(snapshot.findings)
        parent_output.results.extend(snapshot.results)
        parent_output.service_deltas.extend(
            self._get_new_snapshot_service_deltas(snapshot),
        )
        parent_output.scanner_evidence_payloads.extend(
            snapshot.scanner_evidence_payloads,
        )
        parent_output.evidence_store.extend(snapshot.evidence_records)
        self._merge_scanner_data(snapshot.scanner_data)
        self._merge_mapping_lists(
            parent_notes.scanner_warnings,
            snapshot.scanner_warnings,
        )
        self._merge_mapping_lists(
            parent_notes.scanner_coverage_notes,
            snapshot.scanner_coverage_notes,
        )

    def _get_new_snapshot_service_deltas(self, snapshot: Any) -> list[ServiceSpendDelta]:  # noqa: ANN401
        try:
            start_index = int(snapshot.inherited_service_delta_count)
        except (TypeError, ValueError):
            start_index = 0
        return list(snapshot.service_deltas[start_index:])
