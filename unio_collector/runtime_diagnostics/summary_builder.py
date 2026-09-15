from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class RuntimeDiagnosticsSummaryBuilder:
    """Build safe runtime diagnostics summaries for telemetry and reports."""

    def build(  # noqa: D102
        self,
        *,
        events: list[dict[str, Any]],
        run_dir: Path,
        report_files: list[str],
        workflow_timing: dict[str, Any] | None = None,
        phase_timings: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        workflow = workflow_timing or {}
        phases = self._get_phase_timings(workflow, phase_timings)
        artifacts = self._build_artifact_inventory(run_dir, report_files)
        artifact_events = self._select_events(events, "artifact_recorded")
        return {
            "contains_client_result_data": False,
            "status": "available" if events else "no_events_recorded",
            "event_count": len(events),
            "event_counts": self._count_values(events, "event"),
            "phase_event_counts": self._count_values(events, "phase"),
            "scanner_event_count": sum(1 for event in events if event.get("phase") == "scanner_execution"),
            "artifact_event_count": len(artifact_events),
            "slowest_phases": self._build_slowest_phases(phases),
            "slowest_scanners": self._build_slowest_scanners(workflow),
            "largest_artifacts": artifacts[:10],
            "report_generation": self._build_report_generation_summary(workflow),
            "diagnostic_artifacts": {
                "events": "telemetry/runtime-diagnostics.jsonl",
                "summary": "telemetry/runtime-diagnostics-summary.json",
            },
            "limitations": [
                ("Artifact-level write events identify report/export paths and write durations, but they intentionally avoid client payload content."),
            ],
        }

    def _get_phase_timings(
        self,
        workflow_timing: dict[str, Any],
        phase_timings: dict[str, dict[str, Any]] | None,
    ) -> dict[str, dict[str, Any]]:
        workflow_phases = workflow_timing.get("workflow_phase_timings")
        if isinstance(workflow_phases, dict):
            return {str(key): value for key, value in workflow_phases.items() if isinstance(value, dict)}
        return dict(phase_timings or {})

    def _build_slowest_phases(
        self,
        phase_timings: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for phase_name, timing in phase_timings.items():
            duration_ms = self._parse_int(timing.get("duration_ms"))
            if duration_ms is None:
                continue
            records.append(
                {
                    "phase": phase_name,
                    "duration_ms": duration_ms,
                    "started_at": timing.get("started_at"),
                    "completed_at": timing.get("completed_at"),
                },
            )
        return sorted(records, key=lambda item: item["duration_ms"], reverse=True)[:10]

    def _build_slowest_scanners(
        self,
        workflow_timing: dict[str, Any],
    ) -> list[dict[str, Any]]:
        scanners = workflow_timing.get("slowest_scanners")
        if not isinstance(scanners, list):
            return []
        records: list[dict[str, Any]] = []
        for scanner in scanners[:10]:
            if not isinstance(scanner, dict):
                continue
            records.append(
                {
                    "scanner_id": scanner.get("scanner_id"),
                    "status": scanner.get("status"),
                    "duration_ms": scanner.get("duration_ms"),
                    "findings_count": scanner.get("findings_count"),
                },
            )
        return records

    def _build_report_generation_summary(
        self,
        workflow_timing: dict[str, Any],
    ) -> dict[str, Any]:
        report_generation = workflow_timing.get("report_generation_timings")
        if not isinstance(report_generation, dict):
            return {}
        return {
            "duration_ms": report_generation.get("duration_ms"),
            "report_files_generated": report_generation.get(
                "report_files_generated",
            ),
            "phases": report_generation.get("phases", {}),
        }

    def _build_artifact_inventory(
        self,
        run_dir: Path,
        report_files: list[str],
    ) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for relative_path in sorted({str(path) for path in report_files}):
            path = run_dir / relative_path
            if not path.is_file():
                continue
            artifacts.append(
                {
                    "path": relative_path,
                    "size_bytes": path.stat().st_size,
                },
            )
        return sorted(
            artifacts,
            key=lambda item: int(item["size_bytes"]),
            reverse=True,
        )

    def _count_values(
        self,
        events: list[dict[str, Any]],
        key: str,
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in events:
            value = str(event.get(key) or "unknown")
            counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items()))

    def _select_events(
        self,
        events: list[dict[str, Any]],
        event_name: str,
    ) -> list[dict[str, Any]]:
        return [event for event in events if event.get("event") == event_name]

    def _parse_int(self, value: Any) -> int | None:  # noqa: ANN401
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
