from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any

from unio_collector.collector.bundle.schema import BUNDLE_SCHEMA_VERSION
from unio_collector.scanners.registry.boundary_summary import build_scanner_analysis_boundary_summary


@dataclass(frozen=True)
class BundleAnalysisContract:
    """Analyzer contract for the current evidence bundle phase."""

    bundle_schema_version: str = BUNDLE_SCHEMA_VERSION
    contract_type: str = "result_evidence_bundle"
    bundle_purpose: str = "result_evidence"
    analysis_state: str = "completed"
    analyzer_entrypoint: str = "analyze-bundle"
    active_analysis_source: str = "completed_report_bundle"
    deterministic_report_parity: bool = True
    requires_aws_for_analysis: bool = False
    requires_credentials_for_analysis: bool = False
    contains_completed_report_bundle: bool = True
    contains_scanner_execution_results: bool = True
    contains_normalized_evidence_records: bool = True
    strict_evidence_only_analysis_supported: bool = True
    strict_evidence_only_support_scope: str = "all_registered_scanner_analyzers"
    strict_evidence_only_ready_scanner_count: int = 0
    result_bundle_only_scanner_count: int = 0
    strict_evidence_only_report_rebuild_supported: bool = False
    strict_evidence_only_report_rebuild_deferred_reason: str = (
        "All registered scanner analyzers can consume serialized scanner "
        "evidence without AWS clients. The active analyze-bundle report path "
        "still uses the completed ReportBundle to preserve deterministic "
        "report, redaction, readiness, telemetry, and comparison parity while "
        "the report pipeline is split from completed scan results."
    )

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "bundle_schema_version": self.bundle_schema_version,
            "contract_type": self.contract_type,
            "bundle_purpose": self.bundle_purpose,
            "analysis_state": self.analysis_state,
            "analyzer_entrypoint": self.analyzer_entrypoint,
            "active_analysis_source": self.active_analysis_source,
            "deterministic_report_parity": self.deterministic_report_parity,
            "requires_aws_for_analysis": self.requires_aws_for_analysis,
            "requires_credentials_for_analysis": self.requires_credentials_for_analysis,
            "contains_completed_report_bundle": self.contains_completed_report_bundle,
            "contains_scanner_execution_results": (self.contains_scanner_execution_results),
            "contains_normalized_evidence_records": (self.contains_normalized_evidence_records),
            "strict_evidence_only_analysis_supported": (self.strict_evidence_only_analysis_supported),
            "strict_evidence_only_support_scope": (self.strict_evidence_only_support_scope),
            "strict_evidence_only_ready_scanner_count": (self.strict_evidence_only_ready_scanner_count),
            "result_bundle_only_scanner_count": (self.result_bundle_only_scanner_count),
            "strict_evidence_only_report_rebuild_supported": (self.strict_evidence_only_report_rebuild_supported),
            "strict_evidence_only_report_rebuild_deferred_reason": (self.strict_evidence_only_report_rebuild_deferred_reason),
        }


def build_result_bundle_analysis_contract(  # noqa: D103
    *,
    bundle_schema_version: str = BUNDLE_SCHEMA_VERSION,
    strict_evidence_only_report_rebuild_supported: bool = False,
) -> dict[str, Any]:
    summary = build_scanner_analysis_boundary_summary()
    return BundleAnalysisContract(
        bundle_schema_version=bundle_schema_version,
        strict_evidence_only_ready_scanner_count=_get_int(
            summary,
            "strict_evidence_only_ready_count",
        ),
        result_bundle_only_scanner_count=_get_int(
            summary,
            "result_bundle_only_count",
        ),
        strict_evidence_only_report_rebuild_supported=(strict_evidence_only_report_rebuild_supported),
        strict_evidence_only_report_rebuild_deferred_reason=(
            _build_report_rebuild_reason(
                supported=strict_evidence_only_report_rebuild_supported,
            )
        ),
    ).convert_to_dict()


def build_collector_evidence_analysis_contract(  # noqa: D103
    *,
    bundle_schema_version: str,
    coverage_complete: bool,
) -> dict[str, Any]:
    summary = build_scanner_analysis_boundary_summary()
    ready_count = _get_int(summary, "strict_evidence_only_ready_count")
    return BundleAnalysisContract(
        bundle_schema_version=bundle_schema_version,
        contract_type="collector_evidence_bundle",
        bundle_purpose="collector_evidence",
        analysis_state="not_analyzed",
        active_analysis_source="scanner_evidence",
        deterministic_report_parity=False,
        contains_completed_report_bundle=False,
        strict_evidence_only_ready_scanner_count=ready_count,
        result_bundle_only_scanner_count=_get_int(
            summary,
            "result_bundle_only_count",
        ),
        strict_evidence_only_report_rebuild_supported=coverage_complete,
        strict_evidence_only_report_rebuild_deferred_reason=(
            "Complete scanner evidence payload coverage is required before the analyzer can use scanner evidence as its report source."
        ),
    ).convert_to_dict()


def _build_report_rebuild_reason(*, supported: bool) -> str:
    if supported:
        return (
            "Complete scanner evidence payload coverage is present. "
            "The analyzer can use scanner evidence as the report source when "
            "offline replay parity validation passes."
        )
    return BundleAnalysisContract.strict_evidence_only_report_rebuild_deferred_reason


def _get_int(summary: dict[str, object], key: str) -> int:
    value = summary.get(key)
    return value if isinstance(value, int) else 0
