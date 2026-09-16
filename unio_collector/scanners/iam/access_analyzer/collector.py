from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import ProviderResponseError, require_complete_response, require_response_rows, require_response_string
from unio_collector.scanners.access_analyzer.evidence import AccessAnalyzerEvidence
from unio_collector.scanners.access_analyzer.finding_record import (
    AccessAnalyzerFindingRecord,
)
from unio_collector.scanners.access_analyzer.principal import format_access_analyzer_principal
from unio_collector.scanners.access_analyzer.record import AccessAnalyzerRecord
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class IamAccessAnalyzerEvidenceReviewCollector(BaseUnioScanner):
    """Collect provider evidence for iam-access-analyzer-evidence-review."""

    def collect(self, context: ScannerContext) -> AccessAnalyzerEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "accessanalyzer")
        warnings: list[str] = []
        analyzers: list[AccessAnalyzerRecord] = []
        findings: list[AccessAnalyzerFindingRecord] = []
        inventory_status: dict[str, str] = {}
        for region in regions:
            client = context.security.create_client(
                "accessanalyzer",
                region_name=region,
                collector_name="IamAccessAnalyzerEvidenceReviewScanner",
            )
            region_analyzers = self._list_analyzers(client, region, warnings, inventory_status)
            analyzers.extend(region_analyzers)
            for analyzer in region_analyzers:
                findings.extend(self._list_active_findings(client, analyzer, warnings))
        for warning in warnings:
            context.warnings.add(warning)
        return AccessAnalyzerEvidence(
            analyzers=tuple(analyzers),
            findings=tuple(findings),
            regions=tuple(regions),
            warnings=tuple(warnings),
            collection_evidence_version=1,
            analyzer_inventory_status=inventory_status,
        )

    def _list_analyzers(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
        inventory_status: dict[str, str] | None = None,
    ) -> list[AccessAnalyzerRecord]:
        inventory_status = {} if inventory_status is None else inventory_status
        inventory_status[region] = "unavailable"
        try:
            response = client.list_analyzers()
            analyzers = require_response_rows(response, "analyzers")
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"IAM Access Analyzer in {region}", exc)
            return []
        records: list[AccessAnalyzerRecord] = []
        inventory_status[region] = "complete"
        for analyzer in analyzers:
            try:
                arn = require_response_string(analyzer.get("arn"))
                status = require_response_string(analyzer.get("status"))
            except ProviderResponseError as exc:
                append_warning(warnings, f"IAM Access Analyzer in {region}", exc)
                inventory_status[region] = "partial"
                continue
            records.append(
                AccessAnalyzerRecord(
                    analyzer_name=str(analyzer.get("name") or arn.rsplit("/", 1)[-1]),
                    analyzer_arn=arn,
                    analyzer_type=str(analyzer.get("type") or "UNKNOWN"),
                    region=region,
                    status=status,
                ),
            )
        try:
            require_complete_response(response, cursor_keys=("nextToken",))
        except ProviderResponseError as exc:
            append_warning(warnings, f"IAM Access Analyzer in {region}", exc)
            inventory_status[region] = "capped" if exc.aws_error_code == "CappedEvidence" else "partial"
        return records

    def _list_active_findings(
        self,
        client: Any,  # noqa: ANN401
        analyzer: AccessAnalyzerRecord,
        warnings: list[str],
    ) -> list[AccessAnalyzerFindingRecord]:
        records: list[AccessAnalyzerFindingRecord] = []
        try:
            paginator = client.get_paginator("list_findings_v2")
            pages = paginator.paginate(analyzerArn=analyzer.analyzer_arn)
        except Exception:  # noqa: BLE001
            try:
                pages = [client.list_findings_v2(analyzerArn=analyzer.analyzer_arn)]
            except Exception as exc:  # noqa: BLE001
                append_warning(
                    warnings,
                    f"IAM Access Analyzer findings for {analyzer.analyzer_name}",
                    exc,
                )
                return records
        try:
            last_page: object = None
            for page in pages:
                for finding in require_response_rows(page, "findings"):
                    record = self._build_finding_record(finding, analyzer)
                    if record is not None:
                        records.append(record)
                last_page = page
            require_complete_response(last_page, cursor_keys=("nextToken",))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"IAM Access Analyzer findings for {analyzer.analyzer_name}", exc)
        return records

    def _build_finding_record(self, finding: dict[str, Any], analyzer: AccessAnalyzerRecord) -> AccessAnalyzerFindingRecord | None:
        status = require_response_string(finding.get("status"))
        finding_id = require_response_string(finding.get("id"))
        if status.upper() not in {"ACTIVE", "NEW"}:
            return None
        return AccessAnalyzerFindingRecord(
            analyzer_name=analyzer.analyzer_name,
            analyzer_arn=analyzer.analyzer_arn,
            analyzer_type=analyzer.analyzer_type,
            region=analyzer.region,
            finding_id=finding_id,
            finding_type=str(finding.get("findingType") or "UNKNOWN"),
            status=status,
            resource=(str(finding.get("resource")) if finding.get("resource") is not None else None),
            resource_type=(str(finding.get("resourceType")) if finding.get("resourceType") is not None else None),
            principal=format_access_analyzer_principal(finding.get("principal")),
            created_at=finding.get("createdAt"),
            updated_at=finding.get("updatedAt"),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="IamAccessAnalyzerEvidenceReviewScanner",
            implementation_module="unio_collector.scanners.iam.access_analyzer.scanner",
        )
