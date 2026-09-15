from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import require_complete_response, require_response_mapping, require_response_rows, require_response_string
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning
from unio_collector.scanners.security_governance.security_hub.control_record import (
    SecurityHubControlRecord,
)
from unio_collector.scanners.security_governance.security_hub.summary.evidence import (
    SecurityHubControlSummaryEvidence,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class SecurityHubControlSummaryReviewCollector(BaseUnioScanner):
    """Collect provider evidence for securityhub-control-summary-review."""

    def collect(self, context: ScannerContext) -> SecurityHubControlSummaryEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "securityhub")
        warnings: list[str] = []
        records: list[SecurityHubControlRecord] = []
        enabled_regions: list[str] = []
        unavailable_regions: list[str] = []
        not_enabled_regions: list[str] = []
        for region in regions:
            client = context.security.create_client(
                "securityhub",
                region_name=region,
                collector_name="SecurityHubControlSummaryReviewScanner",
            )
            try:
                require_response_mapping(client.describe_hub())
                enabled_regions.append(region)
            except Exception as exc:  # noqa: BLE001
                if aws_errors.is_service_unavailable_error(
                    exc,
                    service_name="securityhub",
                    operation_name="DescribeHub",
                ):
                    not_enabled_regions.append(region)
                else:
                    append_warning(warnings, f"Security Hub controls in {region}", exc)
                    unavailable_regions.append(region)
                continue
            records.extend(self._list_failed_controls(client, region, warnings, unavailable_regions))
        for warning in warnings:
            context.warnings.add(warning)
        return SecurityHubControlSummaryEvidence(
            records=tuple(records),
            regions=tuple(regions),
            enabled_regions=tuple(enabled_regions),
            unavailable_regions=tuple(unavailable_regions),
            not_enabled_regions=tuple(not_enabled_regions),
            warnings=tuple(warnings),
        )

    def _list_failed_controls(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
        unavailable_regions: list[str] | None = None,
    ) -> list[SecurityHubControlRecord]:
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        }
        grouped: dict[str, dict[str, Any]] = {}
        try:
            response = client.get_findings(Filters=filters, MaxResults=100)
            for finding in require_response_rows(response, "Findings"):
                self._add_control_observation(grouped, finding)
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"Security Hub failed controls in {region}", exc)
            if unavailable_regions is not None and region not in unavailable_regions:
                unavailable_regions.append(region)
        return [
            SecurityHubControlRecord(
                region=region,
                control_id=control_id,
                title=str(group["title"]),
                severity_label=str(group["severity_label"]),
                failed_finding_count=int(group["count"]),
                standard_arns=tuple(sorted(group["standard_arns"])),
                resource_types=tuple(sorted(group["resource_types"])),
            )
            for control_id, group in sorted(grouped.items())
        ]

    def _add_control_observation(self, grouped: dict[str, dict[str, Any]], finding: dict[str, Any]) -> None:
        compliance = require_response_mapping(finding.get("Compliance", {}))
        control_id = require_response_string(compliance.get("SecurityControlId") or finding.get("GeneratorId"))
        severity = require_response_mapping(finding.get("Severity", {}))
        product_fields = require_response_mapping(finding.get("ProductFields", {}))
        resources = require_response_rows(finding if "Resources" in finding else {"Resources": []}, "Resources")
        resource_types = {require_response_string(resource["Type"]) for resource in resources if resource.get("Type")}
        standard = product_fields.get("StandardsArn")
        standard_arns = {require_response_string(standard)} if standard else set()
        group = grouped.setdefault(
            control_id,
            {
                "title": require_response_string(finding.get("Title") or control_id),
                "severity_label": require_response_string(severity.get("Label") or "UNKNOWN"),
                "count": 0,
                "standard_arns": set(),
                "resource_types": set(),
            },
        )
        group["count"] += 1
        group["standard_arns"].update(standard_arns)
        group["resource_types"].update(resource_types)

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="SecurityHubControlSummaryReviewScanner",
            implementation_module="unio_collector.scanners.security_governance.security_hub.summary.scanner",
        )
