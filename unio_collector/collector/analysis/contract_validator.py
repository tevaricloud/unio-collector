from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector.bundle.encoding import load_json_object

if TYPE_CHECKING:
    from zipfile import ZipFile


class AnalysisContractValidator:  # noqa: D101
    def validate(  # noqa: C901, D102
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        payload = self._read_json(archive, "analysis-contract.json", errors)
        if not payload:
            return
        if payload.get("bundle_schema_version") != manifest.get(
            "bundle_schema_version",
        ):
            errors.append(
                "analysis-contract.json bundle_schema_version does not match manifest.json.",
            )
        collector_purpose = payload.get("bundle_purpose") == "collector_evidence"
        if payload.get("bundle_purpose", "result_evidence") != manifest.get("bundle_purpose", "result_evidence"):
            errors.append("analysis-contract.json bundle_purpose does not match manifest.json.")
        expected_contract_type = "collector_evidence_bundle" if collector_purpose else "result_evidence_bundle"
        if payload.get("contract_type") != expected_contract_type:
            errors.append(
                f"analysis-contract.json contract_type must be '{expected_contract_type}'.",
            )
        if payload.get("analyzer_entrypoint") != "analyze-bundle":
            errors.append(
                "analysis-contract.json analyzer_entrypoint must be 'analyze-bundle'.",
            )
        expected_analysis_state = "not_analyzed" if collector_purpose else "completed"
        if payload.get("analysis_state") not in (None, expected_analysis_state):
            errors.append(
                "analysis-contract.json analysis_state does not match bundle_purpose.",
            )
        allowed_source = "scanner_evidence" if collector_purpose else "completed_report_bundle"
        if payload.get("active_analysis_source") not in (None, allowed_source):
            errors.append(
                "analysis-contract.json active_analysis_source does not match bundle_purpose.",
            )
        expected_booleans = {
            "deterministic_report_parity": not collector_purpose,
            "requires_aws_for_analysis": False,
            "requires_credentials_for_analysis": False,
            "contains_completed_report_bundle": not collector_purpose,
            "contains_scanner_execution_results": True,
            "contains_normalized_evidence_records": True,
        }
        for key, expected in expected_booleans.items():
            if payload.get(key) is not expected:
                errors.append(
                    f"analysis-contract.json {key} must be {str(expected).lower()}.",
                )
        strict_supported = payload.get("strict_evidence_only_analysis_supported")
        if not isinstance(strict_supported, bool):
            errors.append(
                "analysis-contract.json strict_evidence_only_analysis_supported must be a boolean.",
            )
            return
        if strict_supported:
            self._validate_supported_strict_evidence_contract(
                archive,
                payload,
                errors,
            )
            return
        deferred_reason = payload.get("strict_evidence_only_deferred_reason")
        if not isinstance(deferred_reason, str) or not deferred_reason.strip():
            errors.append(
                "analysis-contract.json strict_evidence_only_deferred_reason must be a non-empty string.",
            )

    def _validate_supported_strict_evidence_contract(
        self,
        archive: ZipFile,
        payload: dict[str, object],
        errors: list[str],
    ) -> None:
        scope = payload.get("strict_evidence_only_support_scope")
        if not isinstance(scope, str) or not scope.strip():
            errors.append(
                "analysis-contract.json strict_evidence_only_support_scope must be a non-empty string.",
            )
        ready_count = payload.get("strict_evidence_only_ready_scanner_count")
        result_only_count = payload.get("result_bundle_only_scanner_count")
        if type(ready_count) is not int or ready_count < 0:
            errors.append(
                "analysis-contract.json strict_evidence_only_ready_scanner_count must be a non-negative integer.",
            )
        if type(result_only_count) is not int or result_only_count < 0:
            errors.append(
                "analysis-contract.json result_bundle_only_scanner_count must be a non-negative integer.",
            )
        rebuild_supported = payload.get(
            "strict_evidence_only_report_rebuild_supported",
        )
        if not isinstance(rebuild_supported, bool):
            errors.append(
                "analysis-contract.json strict_evidence_only_report_rebuild_supported must be a boolean.",
            )
        if rebuild_supported is False:
            reason = payload.get(
                "strict_evidence_only_report_rebuild_deferred_reason",
            )
            if not isinstance(reason, str) or not reason.strip():
                errors.append(
                    "analysis-contract.json strict_evidence_only_report_rebuild_deferred_reason must be a non-empty string.",
                )
        summary = self._read_json(archive, "collection-summary.json", errors)
        boundary = summary.get("scanner_analysis_boundary_summary")
        if not isinstance(boundary, dict):
            return
        if ready_count != boundary.get("strict_evidence_only_ready_count"):
            errors.append(
                "analysis-contract.json strict_evidence_only_ready_scanner_count does not match collection-summary.json.",
            )
        if result_only_count != boundary.get("result_bundle_only_count"):
            errors.append(
                "analysis-contract.json result_bundle_only_scanner_count does not match collection-summary.json.",
            )

    def _read_json(
        self,
        archive: ZipFile,
        name: str,
        errors: list[str],
    ) -> dict[str, object]:
        try:
            return load_json_object(archive.read(name).decode("utf-8"))
        except KeyError:
            return {}
        except Exception:  # noqa: BLE001
            errors.append(f"{name} must contain a valid non-empty JSON object.")
            return {}
