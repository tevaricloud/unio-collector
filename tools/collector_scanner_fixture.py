"""Correlate synthetic actual-scanner payloads with real bundle readiness producers."""

from __future__ import annotations

import json
from typing import Any

from unio_collector.collector.analysis.readiness import add_pricing_replay_readiness, build_strict_analysis_readiness
from unio_collector.scanners.scanner.result import ScannerExecutionResult


def add_scanner_producer_payload(files: dict[str, bytes], primary: dict[str, Any]) -> None:
    """Replace one synthetic producer row and rebuild canonical correlated readiness."""
    scanner_id = primary["scanner_id"]
    member = "scan-result/scanner-evidence.json"
    envelope = json.loads(files[member])
    primary["bundle_schema_version"] = envelope["bundle_schema_version"]

    envelope["scanner_evidence"] = [row for row in envelope["scanner_evidence"] if row["scanner_id"] != scanner_id]
    envelope["scanner_evidence"].append(primary)
    envelope["scanner_evidence_count"] = len(envelope["scanner_evidence"])
    files[member] = json.dumps(envelope, sort_keys=True).encode("utf-8")

    results = json.loads(files["scan-result/scanner-results.json"])
    results["scanner_results"] = [row for row in results["scanner_results"] if row["scanner_id"] != scanner_id]
    results["scanner_results"].append(
        ScannerExecutionResult(
            scanner_id=scanner_id,
            status="completed_with_warnings",
            regions_scanned=["eu-west-2"],
            evidence_count=1,
            warnings=["Synthetic conditional producer cases"],
        ).convert_to_dict()
    )
    files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode("utf-8")
    summary = json.loads(files["collection-summary.json"])
    readiness = build_strict_analysis_readiness(
        summary["scanner_analysis_boundary_summary"],
        bundle_schema_version=envelope["bundle_schema_version"],
        scanner_results=results["scanner_results"],
        scanner_evidence_payloads=envelope["scanner_evidence"],
        provider_id="aws",
        require_successful_scanner_coverage=True,
        active_analysis_source="scanner_evidence",
    )
    add_pricing_replay_readiness(readiness, json.loads(files["scan-result/pricing-context.json"]))
    files["analysis-readiness.json"] = json.dumps(readiness, sort_keys=True).encode("utf-8")
    summary["strict_analysis_readiness"] = readiness
    summary["scanner_count"] = len(results["scanner_results"])
    files["collection-summary.json"] = json.dumps(summary, sort_keys=True).encode("utf-8")
