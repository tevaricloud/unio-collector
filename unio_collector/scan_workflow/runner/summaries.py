from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.summary_contract import (
        ScannerSummaryRuntimeContract,
    )


class ScannerRunSummaryService:
    """Build runtime, scheduler, and cache summaries for a scan runner."""

    def __init__(self, runner: ScannerSummaryRuntimeContract) -> None:  # noqa: D107
        self.runner = runner

    def build_collection_runtime_summary(self) -> dict[str, Any]:
        """Return a safe collection runtime summary from diagnostics."""
        diagnostics = self.runner.runtime_state.collection_diagnostics
        if diagnostics is None:
            return {}
        convert_to_summary = getattr(diagnostics, "convert_to_summary", None)
        if not callable(convert_to_summary):
            return {}
        summary = convert_to_summary()
        return summary if isinstance(summary, dict) else {}

    def build_scheduler_summary(self) -> dict[str, Any]:
        """Build scheduler, implementation, cache, and precheck summary data."""
        schedule_state = self.runner.schedule_state
        plan = schedule_state.scheduler_plan.convert_to_dict() if schedule_state.scheduler_plan else {}
        return {
            "execution_mode": ("bounded_concurrent" if self.runner.runtime_state.runtime_config.scanner_concurrency_enabled else "sequential"),
            "max_workers": (self.runner.runtime_state.runtime_config.scanner_max_workers),
            "plan": plan,
            "stages": [stage_result.convert_to_dict() for stage_result in schedule_state.scheduler_stage_results],
            "scanner_implementation_summary": (self.build_scanner_implementation_summary()),
            "service_usage_precheck": self.build_service_usage_precheck_summary(),
            "shared_evidence_prefetches": (self.build_shared_evidence_prefetch_summary()),
            "contains_client_result_data": False,
        }

    def build_shared_evidence_prefetch_summary(self) -> list[dict[str, Any]]:
        """Build safe summary records for shared evidence prefetches."""
        records: list[dict[str, Any]] = []
        for record in self.runner.evidence_state.shared_evidence_prefetches:
            item = dict(record)
            if not item.get("status") and item.get("cache_access_status"):
                item["status"] = "completed"
            item["contains_client_result_data"] = False
            records.append(item)
        return records

    def build_scanner_implementation_summary(self) -> dict[str, Any]:
        """Count scanner execution results by implementation type."""
        by_type: dict[str, int] = {}
        for result in self.runner.output_state.results:
            implementation_type = result.implementation_type or "unknown"
            by_type[implementation_type] = by_type.get(implementation_type, 0) + 1
        return {
            "contains_client_result_data": False,
            "by_implementation_type": dict(sorted(by_type.items())),
        }

    def build_scan_cache_summary(self) -> dict[str, Any]:
        """Return the AWS scan cache summary."""
        return self.runner.runtime_state.cache.convert_to_summary()

    def build_service_usage_precheck_summary(self) -> dict[str, Any]:
        """Build detailed service-usage precheck decision summary data."""
        schedule_state = self.runner.schedule_state
        summary = schedule_state.service_usage_precheck_policy.build_summary()
        configured_scanner_ids = summary.get("configured_scanner_ids", [])
        if not isinstance(configured_scanner_ids, (list, tuple, set)):
            configured_scanner_ids = []
        configured_ids = {str(scanner_id) for scanner_id in configured_scanner_ids if scanner_id}
        decisions = [
            {
                "scanner_id": decision.scanner_id,
                "status": "run" if decision.should_run else "skipped",
                "reason": decision.reason,
                "matched_services": list(decision.matched_services),
                "configured_service_patterns": list(
                    decision.configured_service_patterns,
                ),
                "precheck_mode": decision.precheck_mode,
                "billing_match_required_to_run": (decision.billing_match_required_to_run),
            }
            for decision in schedule_state.service_usage_precheck_decisions
        ]
        configured_count_value = summary.get("configured_scanner_count") or 0
        configured_count = configured_count_value if isinstance(configured_count_value, int) else int(str(configured_count_value))
        evaluated_count = len(decisions)
        skipped_count = sum(1 for decision in schedule_state.service_usage_precheck_decisions if not decision.should_run)
        summary["scanner_count"] = evaluated_count
        summary["evaluated_scanner_count"] = evaluated_count
        summary["decision_count"] = evaluated_count
        summary["run_count"] = evaluated_count - skipped_count
        summary["skipped_count"] = skipped_count
        summary["not_evaluated_scanner_count"] = max(
            0,
            configured_count - evaluated_count,
        )
        summary["not_evaluated_scanner_ids"] = sorted(
            configured_ids - {decision["scanner_id"] for decision in decisions},
        )
        summary["not_evaluated_decisions"] = self.build_service_usage_precheck_not_evaluated_decisions(
            configured_ids,
            decisions,
        )
        summary["decisions"] = decisions
        return summary

    def build_service_usage_precheck_not_evaluated_decisions(
        self,
        configured_ids: set[str],
        decisions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build synthetic decisions for configured scanners not evaluated."""
        evaluated_ids = {str(decision["scanner_id"]) for decision in decisions}
        result_by_scanner = {str(result.scanner_id): result for result in self.runner.output_state.results if result.scanner_id}
        dependency_map = self.build_attached_dependency_map()
        not_evaluated: list[dict[str, Any]] = []
        for scanner_id in sorted(configured_ids - evaluated_ids):
            result = result_by_scanner.get(scanner_id)
            dependency_id = dependency_map.get(scanner_id)
            status = result.status if result else "not_selected"
            reason = self.build_not_evaluated_reason(
                scanner_id,
                status=status,
                result_reason=result.reason if result else None,
                dependency_id=dependency_id,
            )
            item: dict[str, Any] = {
                "scanner_id": scanner_id,
                "status": status,
                "reason": reason,
                "decision_category": self.build_not_evaluated_category(
                    status=status,
                    result_reason=result.reason if result else None,
                    dependency_id=dependency_id,
                ),
            }
            if dependency_id:
                item["dependency_scanner_id"] = dependency_id
            not_evaluated.append(item)
        return not_evaluated

    def build_not_evaluated_category(
        self,
        *,
        status: str,
        result_reason: str | None,
        dependency_id: str | None,
    ) -> str:
        """Classify why a configured precheck was not evaluated directly."""
        if dependency_id and status == "completed":
            return "dependency_covered"
        if dependency_id:
            return "dependency_not_run"
        if status == "disabled":
            reason = (result_reason or "").casefold()
            if "--only-scanner" in reason:
                return "selected_out"
            return "disabled"
        if status == "not_selected":
            return "selected_out"
        return "other"

    def build_not_evaluated_reason(
        self,
        scanner_id: str,
        *,
        status: str,
        result_reason: str | None,
        dependency_id: str | None,
    ) -> str:
        """Build a human-readable explanation for a non-evaluated precheck."""
        del scanner_id

        if dependency_id and status == "completed":
            return f"Precheck was covered by dependency execution with {dependency_id}; the scanner ran after upstream evidence was collected."
        if dependency_id and status == "skipped":
            return result_reason or (f"Precheck was not evaluated directly because dependency scanner {dependency_id} did not run.")
        if status == "disabled":
            return result_reason or "Scanner was disabled by configuration or selection."
        if result_reason:
            return result_reason
        return "Scanner was not selected for this run or did not reach service-usage precheck evaluation."

    def build_attached_dependency_map(self) -> dict[str, str]:
        """Map attached dependent scanners to their upstream scanner IDs."""
        dependency_map: dict[str, str] = {}
        plan = self.runner.schedule_state.scheduler_plan
        if plan is None:
            return dependency_map
        for stage in plan.stages:
            for dependency_id, dependent_ids in stage.attached_dependents.items():
                for dependent_id in dependent_ids:
                    dependency_map[str(dependent_id)] = str(dependency_id)
        return dependency_map
