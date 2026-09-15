from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector import __version__
from unio_collector.collector.analysis.contract import (
    build_collector_evidence_analysis_contract,
    build_result_bundle_analysis_contract,
)
from unio_collector.collector.analysis.coverage import ScannerEvidenceCoverage
from unio_collector.collector.analysis.readiness import (
    STRICT_ANALYSIS_READINESS_FILE,
    add_pricing_replay_readiness,
    build_strict_analysis_readiness,
)
from unio_collector.collector.bundle.account_scope import infer_partition
from unio_collector.collector.bundle.archive_writer import write_bundle_archive
from unio_collector.collector.bundle.billing_context import get_billing_context_summary
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector.bundle.encoding import dump_json, dump_jsonl, validate_internal_path
from unio_collector.collector.bundle.permission_degradation import (
    build_permission_degradation_payload,
    build_permission_degradation_records,
    build_permission_limitation_payload,
)
from unio_collector.collector.bundle.region_scope import (
    build_region_scope_limitations,
    get_region_scope_summary,
)
from unio_collector.collector.bundle.result_selector import get_bundle_scanner_results
from unio_collector.collector.bundle.scan_period import serialize_scan_period
from unio_collector.collector.bundle.scanner_evidence_payloads import (
    build_scanner_evidence_payloads,
)
from unio_collector.collector.bundle.schema import (
    COLLECTION_MODE,
    SERVICE_EVIDENCE_FILES,
    BundleSchema,
    schema_version_for_bundle_purpose,
)
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.bundle.write_result import BundleWriteResult
from unio_collector.collector.evidence.service_map import get_service_evidence_file
from unio_collector.collector.minimisation import (
    EvidenceMinimisationOptions,
    normalize_service_name,
)
from unio_collector.collector.permission.export import PermissionExportBuilder
from unio_collector.collector.signature import build_unsigned_signature_metadata
from unio_collector.evidence.permission.planning import summarize_degradation_records
from unio_collector.scanners.registry.boundary_summary import build_scanner_analysis_boundary_summary

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.bundle.source import EvidenceBundleSource


class EvidencePayloadWriter:
    """Serialize prepared bundle facts without deriving evidence from findings."""

    def write(
        self,
        *,
        path: Path,
        bundle: EvidenceBundleSource,
        scan_result: Any,  # noqa: ANN401
        config: Any,  # noqa: ANN401
        minimisation: EvidenceMinimisationOptions | None = None,
        bundle_purpose: str = "collector_evidence",
    ) -> BundleWriteResult:
        """Write a bundle ZIP and return its manifest metadata."""
        options = minimisation or EvidenceMinimisationOptions()
        path.parent.mkdir(parents=True, exist_ok=True)
        files = self._build_payload_files(
            bundle=bundle,
            scan_result=scan_result,
            config=config,
            minimisation=options,
            bundle_purpose=bundle_purpose,
        )
        checksums = build_checksums(files)
        manifest = self._build_manifest(
            bundle=bundle,
            scan_result=scan_result,
            config=config,
            minimisation=options,
            checksums=checksums,
            evidence_files=[name for name in sorted(files) if name.startswith(("evidence/", "scan-result/"))],
            bundle_purpose=bundle_purpose,
        )
        files["manifest.json"] = dump_json(manifest)
        files["checksums.json"] = dump_json(
            {"algorithm": "sha256", "checksums": checksums},
        )
        write_bundle_archive(
            path,
            files,
            validate_path=validate_internal_path,
            validate_archive=EvidenceBundleValidator().validate_or_raise,
        )
        return BundleWriteResult(path=path, manifest=manifest)

    def _build_payload_files(
        self,
        *,
        bundle: EvidenceBundleSource,
        scan_result: Any,  # noqa: ANN401
        config: Any,  # noqa: ANN401
        minimisation: EvidenceMinimisationOptions,
        bundle_purpose: str,
    ) -> dict[str, bytes]:
        scanner_results = get_bundle_scanner_results(
            scan_result,
            bundle_purpose=bundle_purpose,
        )
        schema_version = schema_version_for_bundle_purpose(bundle_purpose)
        scanner_evidence_payloads = build_scanner_evidence_payloads(
            getattr(scan_result, "scanner_evidence_payloads", []),
            schema_version=schema_version,
        )
        evidence_records = bundle.evidence_records
        collection_records = list(getattr(scan_result.ledger, "records", []))
        account_scope = self._build_account_scope(bundle, scanner_results)
        degradation_records = build_permission_degradation_records(
            bundle=bundle,
            scan_result=scan_result,
            collection_records=collection_records,
            scanner_results=scanner_results,
        )
        permission_summary = PermissionExportBuilder().build(
            bundle=bundle,
            config=config,
            scan_result=scan_result,
            degradation_records=degradation_records,
        )
        scanner_boundary_summary = build_scanner_analysis_boundary_summary()
        strict_analysis_readiness = build_strict_analysis_readiness(
            scanner_boundary_summary,
            scanner_results=scanner_results,
            scanner_evidence_payloads=scanner_evidence_payloads,
            provider_id=str(getattr(scan_result, "provider_id", "aws") or "aws"),
            bundle_schema_version=schema_version,
            require_successful_scanner_coverage=(bundle_purpose == "collector_evidence"),
            active_analysis_source=("scanner_evidence" if bundle_purpose == "collector_evidence" else "completed_report_bundle"),
        )
        pricing_context = getattr(scan_result, "pricing_context", None)
        add_pricing_replay_readiness(strict_analysis_readiness, pricing_context)
        coverage = ScannerEvidenceCoverage.assess(
            scanner_results=scanner_results,
            scanner_evidence_payloads=scanner_evidence_payloads,
            provider_id=str(getattr(scan_result, "provider_id", "aws") or "aws"),
        )
        rebuild_supported = bool(
            strict_analysis_readiness.get(
                "full_report_rebuild_from_scanner_evidence_supported",
            ),
        )
        collection_summary = self._build_collection_summary(
            bundle=bundle,
            scan_result=scan_result,
            scanner_results=scanner_results,
            minimisation=minimisation,
            scanner_boundary_summary=scanner_boundary_summary,
            strict_analysis_readiness=strict_analysis_readiness,
            degradation_records=degradation_records,
        )
        service_files = self._build_service_files(
            scanner_results=scanner_results,
            evidence_records=evidence_records,
            minimisation=minimisation,
        )
        files = {
            "analysis-contract.json": dump_json(
                build_collector_evidence_analysis_contract(
                    bundle_schema_version=schema_version,
                    coverage_complete=coverage.complete,
                )
                if bundle_purpose == "collector_evidence"
                else build_result_bundle_analysis_contract(
                    bundle_schema_version=schema_version,
                    strict_evidence_only_report_rebuild_supported=rebuild_supported,
                ),
            ),
            STRICT_ANALYSIS_READINESS_FILE: dump_json(
                strict_analysis_readiness,
            ),
            "bundle-schema.json": dump_json(
                BundleSchema(schema_version=schema_version).convert_to_dict(),
            ),
            "collector-version.json": dump_json(
                {
                    "collector_version": __version__,
                    "package_version": __version__,
                },
            ),
            "account-scope.json": dump_json(account_scope),
            "permissions-summary.json": dump_json(permission_summary),
            "permissions/degradation-records.json": dump_json(
                build_permission_degradation_payload(degradation_records),
            ),
            "collection-summary.json": dump_json(collection_summary),
            "collection-log.jsonl": dump_jsonl(collection_records),
            "scan-result/report-bundle.json": dump_json(
                bundle.compatibility_payload,
            ),
            "scan-result/scanner-results.json": dump_json(
                {"scanner_results": scanner_results},
            ),
            "scan-result/scanner-evidence.json": dump_json(
                {
                    "bundle_schema_version": schema_version,
                    "payload_format": "unio-scanner-evidence-v1",
                    "scanner_evidence": scanner_evidence_payloads,
                    "scanner_evidence_count": len(scanner_evidence_payloads),
                },
            ),
            "scan-result/evidence-records.json": dump_json(
                {"records": evidence_records},
            ),
            "scan-result/api-runtime-summary.json": dump_json(
                getattr(scan_result, "api_telemetry", {}) or {},
            ),
            "evidence/normalized-evidence.json": dump_json(
                {"records": evidence_records},
            ),
            "signature.json": dump_json(
                build_unsigned_signature_metadata(metadata_version=schema_version),
            ),
        }
        if isinstance(pricing_context, dict):
            files["scan-result/pricing-context.json"] = dump_json(pricing_context)
        files.update(service_files)
        return files

    def _build_manifest(
        self,
        *,
        bundle: EvidenceBundleSource,
        scan_result: Any,  # noqa: ANN401
        config: Any,  # noqa: ANN401
        minimisation: EvidenceMinimisationOptions,
        checksums: dict[str, str],
        evidence_files: list[str],
        bundle_purpose: str,
    ) -> dict[str, Any]:
        scanner_results = get_bundle_scanner_results(
            scan_result,
            bundle_purpose=bundle_purpose,
        )
        services_attempted = self._get_services_attempted(scanner_results)
        services_unavailable = self._get_services_unavailable(
            scanner_results,
            minimisation,
        )
        services_collected = [service for service in services_attempted if service not in set(services_unavailable)]
        degradation_records = build_permission_degradation_records(
            bundle=bundle,
            scan_result=scan_result,
            collection_records=list(getattr(scan_result.ledger, "records", [])),
            scanner_results=scanner_results,
        )
        permission_limitations = [
            *minimisation.build_limitations(),
            *build_region_scope_limitations(bundle),
            *build_permission_limitation_payload(degradation_records),
        ]
        region_scope = get_region_scope_summary(bundle)
        product_execution = dict(bundle.summary.get("scan_manifest") or {}).get("product_execution")
        return {
            "bundle_schema_version": schema_version_for_bundle_purpose(
                bundle_purpose,
            ),
            "collector_version": __version__,
            "collection_mode": COLLECTION_MODE,
            "bundle_purpose": bundle_purpose,
            "analysis_state": ("not_analyzed" if bundle_purpose == "collector_evidence" else "completed"),
            "collection_status": str(
                getattr(scan_result, "collection_status", "") or self._collection_status(scanner_results),
            ),
            "generated_at": datetime.now(UTC).isoformat(),
            "evidence_generated_at": bundle.generated_at.isoformat(),
            "account_id": str(
                bundle.account_context.get("account_id") or "unknown-account",
            ),
            "partition": infer_partition(bundle),
            "regions": self._get_regions(bundle, scanner_results),
            "region_scope": region_scope,
            "services_attempted": services_attempted,
            "services_collected": services_collected,
            "services_unavailable": services_unavailable,
            "permission_limitations": permission_limitations,
            "permission_degradation_record_count": len(degradation_records),
            "evidence_files": evidence_files,
            "checksums": checksums,
            "redaction_or_minimisation": minimisation.convert_to_manifest_payload(),
            "source": {
                "type": ("collector_evidence" if bundle_purpose == "collector_evidence" else "result_bundle"),
                "fixture": str(getattr(config, "fixture", None) or "") or None,
                "profile_name": getattr(config, "profile", None),
                "replay_aws_cassette": str(
                    getattr(getattr(config, "runtime", None), "replay_aws_cassette", "") or "",
                )
                or None,
            },
            **({"product_execution": product_execution} if product_execution is not None else {}),
        }

    def _build_account_scope(
        self,
        bundle: EvidenceBundleSource,
        scanner_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        account_scope = {
            "account_context": bundle.account_context,
            "account_id": str(
                bundle.account_context.get("account_id") or "unknown-account",
            ),
            "partition": infer_partition(bundle),
            "regions": self._get_regions(bundle, scanner_results),
            "scan_period": serialize_scan_period(bundle.scan_period),
        }
        region_scope = get_region_scope_summary(bundle)
        if region_scope:
            account_scope["region_scope"] = region_scope
        return account_scope

    def _build_collection_summary(
        self,
        *,
        bundle: EvidenceBundleSource,
        scan_result: Any,  # noqa: ANN401
        scanner_results: list[dict[str, Any]],
        minimisation: EvidenceMinimisationOptions,
        scanner_boundary_summary: dict[str, object],
        strict_analysis_readiness: dict[str, Any],
        degradation_records: tuple[Any, ...],
    ) -> dict[str, Any]:
        degradation_summary = summarize_degradation_records(degradation_records)
        return {
            "generated_at": bundle.generated_at.isoformat(),
            "scanner_count": len(scanner_results),
            "finding_count": bundle.finding_count,
            "evidence_count": len(scan_result.evidence_store.get_records()),
            "api_call_count": len(getattr(scan_result.ledger, "records", [])),
            "api_runtime_summary": getattr(scan_result, "api_telemetry", {}) or {},
            "collection_runtime_summary": bundle.summary.get("collection_runtime_summary", {}),
            "scanner_analysis_boundary_summary": scanner_boundary_summary,
            "strict_analysis_readiness": strict_analysis_readiness,
            "minimisation": minimisation.convert_to_manifest_payload(),
            "limitations": [
                *minimisation.build_limitations(),
                *build_region_scope_limitations(bundle),
            ],
            "collection_status": str(
                getattr(scan_result, "collection_status", "") or self._collection_status(scanner_results),
            ),
            "permission_degradation_record_count": len(degradation_records),
            "limitation_count": degradation_summary.get("limitation_count", 0),
            "limitation_counts": degradation_summary.get("limitation_counts", {}),
            "stable_limitation_counts": degradation_summary.get(
                "stable_limitation_counts",
                {},
            ),
            "stable_limitation_details": degradation_summary.get(
                "stable_limitation_details",
                [],
            ),
            "secondary_classification_counts": degradation_summary.get("secondary_classification_counts", {}),
            "region_scope": get_region_scope_summary(bundle),
            **get_billing_context_summary(bundle),
        }

    def _collection_status(self, scanner_results: list[dict[str, Any]]) -> str:
        statuses = {str(result.get("status") or "") for result in scanner_results}
        successful = statuses.intersection({"completed", "completed_with_warnings"})
        if not successful:
            return "failed"
        if (
            statuses.intersection(
                {"disabled", "failed", "permission_denied", "skipped", "unavailable"},
            )
            or "completed_with_warnings" in statuses
        ):
            return "degraded"
        return "complete"

    def _build_service_files(
        self,
        *,
        scanner_results: list[dict[str, Any]],
        evidence_records: list[dict[str, Any]],
        minimisation: EvidenceMinimisationOptions,
    ) -> dict[str, bytes]:
        attempted = set(self._get_services_attempted(scanner_results))
        unavailable = set(self._get_services_unavailable(scanner_results, minimisation))
        by_file = {path: [] for path in SERVICE_EVIDENCE_FILES}
        for record in evidence_records:
            service = normalize_service_name(record.get("service") or "")
            path = get_service_evidence_file(service)
            if path in by_file:
                by_file[path].append(record)
        files: dict[str, bytes] = {}
        for path in SERVICE_EVIDENCE_FILES:
            service = path.removeprefix("evidence/").removesuffix(".json")
            status = "collected" if service in attempted else "not_attempted"
            if service in unavailable:
                status = "unavailable"
            if service in minimisation.exclude_services:
                status = "excluded"
            if minimisation.no_cost_data and service == "cost-explorer":
                status = "excluded"
            files[path] = dump_json(
                {
                    "service": service,
                    "status": status,
                    "records": by_file[path],
                    "limitations": [item for item in minimisation.build_limitations() if item.get("service") in {service, "all"}],
                },
            )
        return files

    def _get_services_attempted(self, scanner_results: list[dict[str, Any]]) -> list[str]:
        services: set[str] = set()
        for result in scanner_results:
            if result.get("status") in {"disabled", "skipped"}:
                continue
            for call in result.get("aws_api_calls", []) or []:
                service = str(call).split(":", 1)[0]
                if service:
                    services.add(normalize_service_name(service))
        return sorted(services)

    def _get_services_unavailable(
        self,
        scanner_results: list[dict[str, Any]],
        minimisation: EvidenceMinimisationOptions,
    ) -> list[str]:
        services = set(minimisation.exclude_services)
        if minimisation.no_cost_data:
            services.add("cost-explorer")
            services.add("ce")
        for result in scanner_results:
            if result.get("status") not in {
                "permission_denied",
                "unavailable",
                "failed",
            }:
                continue
            for call in result.get("aws_api_calls", []) or []:
                service = str(call).split(":", 1)[0]
                if service:
                    services.add(normalize_service_name(service))
        return sorted(services)

    def _get_regions(
        self,
        bundle: EvidenceBundleSource,
        scanner_results: list[dict[str, Any]],
    ) -> list[str]:
        regions: set[str] = set()
        manifest = bundle.summary.get("scan_manifest")
        if isinstance(manifest, dict):
            for key in ("scanned_regions", "selected_regions", "regions"):
                for region in manifest.get(key, []) or []:
                    if str(region).lower() != "local":
                        regions.add(str(region))
        for result in scanner_results:
            for region in result.get("regions_scanned", []) or []:
                if str(region).lower() != "local":
                    regions.add(str(region))
        return sorted(regions)
