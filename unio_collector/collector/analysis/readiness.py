from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any

from unio_collector.collector.analysis.coverage import ScannerEvidenceCoverage
from unio_collector.collector.bundle.schema import BUNDLE_SCHEMA_VERSION

STRICT_ANALYSIS_READINESS_FILE = "analysis-readiness.json"
STRICT_ANALYSIS_REQUIRED_PAYLOAD_FILE = "scan-result/scanner-evidence.json"
STRICT_ANALYSIS_REBUILD_DEFERRED_REASON = (
    "Scanner evidence payload serialization is available, but full report "
    "rebuild from strict scanner evidence remains deferred until the offline "
    "scanner-evidence replay runner and report parity validation are complete."
)
STRICT_ANALYSIS_REBUILD_READY_REASON = (
    "Complete scanner evidence payload coverage is present. The offline "
    "analyzer can use scanner evidence as the report source when replay "
    "parity validation passes."
)


@dataclass(frozen=True)
class StrictAnalysisReadiness:  # noqa: D101
    bundle_schema_version: str = BUNDLE_SCHEMA_VERSION
    active_analysis_source: str = "completed_report_bundle"
    strict_scanner_analyzer_replay_supported: bool = True
    strict_scanner_analyzer_replay_scope: str = "all_registered_scanner_analyzers"
    full_report_rebuild_from_scanner_evidence_supported: bool = False
    scanner_evidence_payloads_serialized: bool = False
    scanner_evidence_payload_file: str = STRICT_ANALYSIS_REQUIRED_PAYLOAD_FILE
    scanner_evidence_payload_count: int = 0
    missing_scanner_evidence_payload_ids: tuple[str, ...] = field(default_factory=tuple)
    required_for_full_report_rebuild: tuple[str, ...] = (
        "scanner-evidence replay runner",
        "report parity validation",
    )
    deferred_reason: str = STRICT_ANALYSIS_REBUILD_DEFERRED_REASON
    scanner_count: int = 0
    strict_evidence_only_ready_count: int = 0
    result_bundle_only_count: int = 0
    deferred_scanner_ids: tuple[str, ...] = field(default_factory=tuple)

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "bundle_schema_version": self.bundle_schema_version,
            "active_analysis_source": self.active_analysis_source,
            "strict_scanner_analyzer_replay_supported": (self.strict_scanner_analyzer_replay_supported),
            "strict_scanner_analyzer_replay_scope": (self.strict_scanner_analyzer_replay_scope),
            "full_report_rebuild_from_scanner_evidence_supported": (self.full_report_rebuild_from_scanner_evidence_supported),
            "scanner_evidence_payloads_serialized": (self.scanner_evidence_payloads_serialized),
            "scanner_evidence_payload_file": self.scanner_evidence_payload_file,
            "scanner_evidence_payload_count": self.scanner_evidence_payload_count,
            "missing_scanner_evidence_payload_ids": list(
                self.missing_scanner_evidence_payload_ids,
            ),
            "required_for_full_report_rebuild": list(
                self.required_for_full_report_rebuild,
            ),
            "deferred_reason": self.deferred_reason,
            "scanner_count": self.scanner_count,
            "strict_evidence_only_ready_count": (self.strict_evidence_only_ready_count),
            "result_bundle_only_count": self.result_bundle_only_count,
            "deferred_scanner_ids": list(self.deferred_scanner_ids),
        }


def build_strict_analysis_readiness(  # noqa: D103
    scanner_boundary_summary: dict[str, object],
    *,
    bundle_schema_version: str = BUNDLE_SCHEMA_VERSION,
    scanner_results: list[dict[str, Any]] | None = None,
    scanner_evidence_payloads: list[dict[str, Any]] | None = None,
    provider_id: str | None = None,
    require_successful_scanner_coverage: bool = False,
    active_analysis_source: str = "completed_report_bundle",
) -> dict[str, Any]:
    payloads = list(scanner_evidence_payloads or [])
    coverage = ScannerEvidenceCoverage.assess(
        scanner_results=scanner_results or [],
        scanner_evidence_payloads=payloads,
        provider_id=provider_id,
    )
    if require_successful_scanner_coverage:
        missing_payload_ids = list(coverage.missing_payload_ids)
        payloads_serialized = coverage.complete
    else:
        missing_payload_ids = _get_legacy_missing_payload_ids(
            scanner_results or [],
            payloads,
        )
        payloads_serialized = bool(payloads) and not missing_payload_ids
    return StrictAnalysisReadiness(
        bundle_schema_version=bundle_schema_version,
        active_analysis_source=active_analysis_source,
        full_report_rebuild_from_scanner_evidence_supported=payloads_serialized,
        scanner_evidence_payloads_serialized=payloads_serialized,
        scanner_evidence_payload_count=len(payloads),
        missing_scanner_evidence_payload_ids=tuple(missing_payload_ids),
        required_for_full_report_rebuild=(
            _build_remaining_rebuild_requirements(
                payloads_serialized=payloads_serialized,
            )
        ),
        deferred_reason=_build_deferred_reason(
            payloads_serialized=payloads_serialized,
        ),
        scanner_count=_get_int(scanner_boundary_summary, "scanner_count"),
        strict_evidence_only_ready_count=_get_int(
            scanner_boundary_summary,
            "strict_evidence_only_ready_count",
        ),
        result_bundle_only_count=_get_int(
            scanner_boundary_summary,
            "result_bundle_only_count",
        ),
        deferred_scanner_ids=_get_string_tuple(
            scanner_boundary_summary,
            "deferred_scanner_ids",
        ),
    ).convert_to_dict() | {"scanner_evidence_coverage": coverage.convert_to_dict()}


def add_pricing_replay_readiness(
    readiness: dict[str, Any],
    pricing_context: object,
) -> None:
    """Add pricing replay readiness when typed context was collected."""
    if not isinstance(pricing_context, dict):
        return
    status = pricing_context.get("status", "unknown")
    readiness["pricing_replay"] = {
        "status": status,
        "context_file": "scan-result/pricing-context.json",
        "context_serialized": True,
        "financial_parity_candidate": status in {"loaded", "partial"},
    }


def _get_legacy_missing_payload_ids(
    scanner_results: list[dict[str, Any]],
    payloads: list[dict[str, Any]],
) -> list[str]:
    expected = {str(result.get("scanner_id")) for result in scanner_results if result.get("scanner_id")}
    actual = {str(payload.get("scanner_id")) for payload in payloads if payload.get("scanner_id")}
    return sorted(expected - actual)


def _build_remaining_rebuild_requirements(
    *,
    payloads_serialized: bool,
) -> tuple[str, ...]:
    requirements = [
        "scanner-evidence replay runner",
        "report parity validation",
    ]
    if payloads_serialized:
        return ()
    if not payloads_serialized:
        requirements.insert(0, "complete scanner evidence payload coverage")
    return tuple(requirements)


def _build_deferred_reason(*, payloads_serialized: bool) -> str:
    if payloads_serialized:
        return STRICT_ANALYSIS_REBUILD_READY_REASON
    return (
        "Full report rebuild from strict scanner evidence is deferred because "
        "this bundle does not include complete scanner evidence payload "
        "coverage. Fixture-imported bundles may only contain completed report "
        "results, scanner execution metadata, and normalized EvidenceRecord rows."
    )


def _get_int(summary: dict[str, object], key: str) -> int:
    value = summary.get(key)
    return value if isinstance(value, int) else 0


def _get_string_tuple(summary: dict[str, object], key: str) -> tuple[str, ...]:
    value = summary.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))
