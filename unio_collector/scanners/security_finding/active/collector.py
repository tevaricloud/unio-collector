from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_finding.active.evidence import (
    ActiveSecurityFindingEvidence,
)
from unio_collector.scanners.security_finding.provider import (
    append_securityhub_unavailable_warning,
    extract_guardduty_resource,
    extract_securityhub_resource,
    retain_provider_severity,
    securityhub_finding_is_inactive,
    securityhub_findings_unavailable,
)
from unio_collector.scanners.security_finding.record import SecurityFindingRecord
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.values import chunk_values
from unio_collector.scanners.security_governance.collection.warnings import append_warning, record_context_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class ActiveSecurityFindingReviewCollector(BaseUnioScanner):
    """Collect provider evidence for active-security-finding-review."""

    def collect(self, context: ScannerContext) -> ActiveSecurityFindingEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "securityhub")
        warnings: list[str] = []
        records: list[SecurityFindingRecord] = []
        for region in regions:
            records.extend(self._collect_guardduty(context, region, warnings))
            records.extend(self._collect_securityhub(context, region, warnings))
        for warning in warnings:
            context.warnings.add(warning)
        return ActiveSecurityFindingEvidence(
            findings=tuple(records),
            regions=tuple(regions),
            warnings=tuple(warnings),
            collection_evidence_version=1,
        )

    def _collect_guardduty(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[SecurityFindingRecord]:
        client = context.security.create_client(
            "guardduty",
            region_name=region,
            collector_name="ActiveSecurityFindingReviewScanner",
        )
        try:
            detector_ids = client.list_detectors().get("DetectorIds", [])
        except Exception as exc:  # noqa: BLE001
            record_context_warning(context, warnings, region, "GuardDuty findings", exc)
            return []
        records: list[SecurityFindingRecord] = []
        for detector_id in detector_ids if isinstance(detector_ids, list) else []:
            finding_ids = self._list_guardduty_finding_ids(
                client,
                str(detector_id),
                region,
                warnings,
            )
            for chunk in chunk_values(finding_ids, 50):
                records.extend(
                    self._get_guardduty_findings(
                        context,
                        client,
                        str(detector_id),
                        chunk,
                        region,
                        warnings,
                    ),
                )
        return records

    def _list_guardduty_finding_ids(
        self,
        client: Any,  # noqa: ANN401
        detector_id: str,
        region: str,
        warnings: list[str],
    ) -> list[str]:
        criteria = {
            "Criterion": {
                "service.archived": {"Eq": ["false"]},
            },
        }
        try:
            paginator = client.get_paginator("list_findings")
            pages = paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria=criteria,
            )
        except Exception:  # noqa: BLE001
            try:
                pages = [
                    client.list_findings(
                        DetectorId=detector_id,
                        FindingCriteria=criteria,
                    ),
                ]
            except Exception as exc:  # noqa: BLE001
                append_warning(
                    warnings,
                    f"GuardDuty finding list in {region}",
                    exc,
                )
                return []
        return [str(finding_id) for page in pages for finding_id in page.get("FindingIds", []) if finding_id]

    def _get_guardduty_findings(
        self,
        context: ScannerContext,
        client: Any,  # noqa: ANN401
        detector_id: str,
        finding_ids: list[str],
        region: str,
        warnings: list[str],
    ) -> list[SecurityFindingRecord]:
        if not finding_ids:
            return []
        try:
            response = client.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids,
            )
        except Exception as exc:  # noqa: BLE001
            record_context_warning(
                context,
                warnings,
                region,
                "GuardDuty findings",
                exc,
            )
            return []
        records: list[SecurityFindingRecord] = []
        for finding in response.get("Findings", []):
            if not isinstance(finding, dict) or not finding.get("Id"):
                continue
            resource_type, resource_id = extract_guardduty_resource(finding)
            records.append(
                SecurityFindingRecord(
                    provider="GuardDuty",
                    finding_id=str(finding["Id"]),
                    region=str(finding.get("Region") or "global"),
                    title=str(finding.get("Title") or finding.get("Type") or ""),
                    description=finding.get("Description"),
                    severity=retain_provider_severity(
                        finding.get("Severity"),
                    ),
                    resource_type=resource_type,
                    resource_id=resource_id,
                    finding_type=finding.get("Type"),
                    workflow_status="active",
                    record_state="active",
                    updated_at=finding.get("UpdatedAt"),
                ),
            )
        return records

    def _collect_securityhub(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[SecurityFindingRecord]:
        client = context.security.create_client(
            "securityhub",
            region_name=region,
            collector_name="ActiveSecurityFindingReviewScanner",
        )
        try:
            pages = client.get_paginator("get_findings").paginate()
        except Exception:  # noqa: BLE001
            try:
                pages = [client.get_findings()]
            except Exception as exc:  # noqa: BLE001
                if securityhub_findings_unavailable(exc):
                    append_securityhub_unavailable_warning(warnings, region)
                    return []
                record_context_warning(
                    context,
                    warnings,
                    region,
                    "Security Hub findings",
                    exc,
                )
                return []
        records: list[SecurityFindingRecord] = []
        try:
            for page in pages:
                for finding in page.get("Findings", []):
                    if not isinstance(finding, dict) or not finding.get("Id"):
                        continue
                    if securityhub_finding_is_inactive(finding):
                        continue
                    resource_type, resource_id = extract_securityhub_resource(finding)
                    records.append(
                        SecurityFindingRecord(
                            provider="Security Hub",
                            finding_id=str(finding["Id"]),
                            region=str(finding.get("Region") or region),
                            title=str(finding.get("Title") or ""),
                            description=finding.get("Description"),
                            severity=retain_provider_severity(
                                finding.get("Severity", {}).get("Label") if isinstance(finding.get("Severity"), dict) else finding.get("Severity"),
                            ),
                            resource_type=resource_type,
                            resource_id=resource_id,
                            finding_type=finding.get("Types", [None])[0] if isinstance(finding.get("Types"), list) else None,
                            workflow_status=(finding.get("Workflow", {}).get("Status") if isinstance(finding.get("Workflow"), dict) else None),
                            record_state=finding.get("RecordState"),
                            updated_at=finding.get("UpdatedAt"),
                        ),
                    )
        except Exception as exc:  # noqa: BLE001
            if securityhub_findings_unavailable(exc):
                append_securityhub_unavailable_warning(warnings, region)
                return records
            record_context_warning(
                context,
                warnings,
                region,
                "Security Hub findings",
                exc,
            )
        return records

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ActiveSecurityFindingReviewScanner",
            implementation_module="unio_collector.scanners.security_finding.active.scanner",
        )
