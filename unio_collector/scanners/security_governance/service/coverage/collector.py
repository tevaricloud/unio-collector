from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import (
    require_complete_response,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
    require_response_strings,
)
from unio_collector.scanners.audit_cost.cloudtrail.facts import count_cloudtrail_multi_region_trails, count_cloudtrail_organization_trails
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.regional.security_service_record import (
    RegionalSecurityServiceRecord,
)
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning, record_context_warning
from unio_collector.scanners.security_governance.service.coverage.evidence import (
    SecurityServiceCoverageEvidence,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class AwsSecurityServiceCoverageReviewCollector(BaseUnioScanner):
    """Collect provider evidence for aws-security-service-coverage-review."""

    def collect(self, context: ScannerContext) -> SecurityServiceCoverageEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "ec2")
        warnings: list[str] = []
        records: list[RegionalSecurityServiceRecord] = []
        records.extend(self._collect_cloudtrail(context, regions, warnings))
        records.extend(self._collect_config(context, regions, warnings))
        records.extend(self._collect_guardduty(context, regions, warnings))
        records.extend(self._collect_securityhub(context, regions, warnings))
        for warning in warnings:
            context.warnings.add(warning)
        return SecurityServiceCoverageEvidence(
            records=tuple(records),
            regions=tuple(regions),
            warnings=tuple(warnings),
        )

    def _collect_cloudtrail(
        self,
        context: ScannerContext,
        regions: list[str],
        warnings: list[str],
    ) -> list[RegionalSecurityServiceRecord]:
        records: list[RegionalSecurityServiceRecord] = []
        for region in regions:
            client = self._create_client(context, "cloudtrail", region)
            try:
                response = client.describe_trails(includeShadowTrails=True)
                trails = require_response_rows(response, "trailList")
                require_complete_response(response)
                for trail in trails:
                    require_response_bool(trail.get("IsOrganizationTrail"))
                    require_response_bool(trail.get("IsMultiRegionTrail"))
            except Exception as exc:  # noqa: BLE001
                record_context_warning(context, warnings, region, "CloudTrail", exc)
                records.append(
                    RegionalSecurityServiceRecord(
                        service_name="CloudTrail",
                        region=region,
                        enabled=None,
                        detail="CloudTrail visibility unavailable.",
                    ),
                )
                continue
            enabled = bool(trails)
            organization_trail_count = count_cloudtrail_organization_trails(trails)
            multi_region_trail_count = count_cloudtrail_multi_region_trails(trails)
            records.append(
                RegionalSecurityServiceRecord(
                    service_name="CloudTrail",
                    region=region,
                    enabled=enabled,
                    detail=(
                        f"{len(trails)} trail records visible; {multi_region_trail_count} multi-region; {organization_trail_count} organisation trails."
                        if isinstance(trails, list)
                        else "Trail response was not list-shaped."
                    ),
                    metadata={
                        "visible_trail_count": len(trails) if isinstance(trails, list) else 0,
                        "multi_region_trail_count": multi_region_trail_count,
                        "organization_trail_count": organization_trail_count,
                    },
                ),
            )
        return records

    def _collect_config(
        self,
        context: ScannerContext,
        regions: list[str],
        warnings: list[str],
    ) -> list[RegionalSecurityServiceRecord]:
        records: list[RegionalSecurityServiceRecord] = []
        for region in regions:
            client = self._create_client(context, "config", region)
            try:
                recorders = require_response_rows(
                    client.describe_configuration_recorders(),
                    "ConfigurationRecorders",
                )
                statuses = require_response_rows(
                    client.describe_configuration_recorder_status(),
                    "ConfigurationRecordersStatus",
                )
                recording_states = [require_response_bool(status.get("recording")) for status in statuses]
                recorder_names = {require_response_string(recorder.get("name")) for recorder in recorders}
                status_names = {require_response_string(status.get("name")) for status in statuses}
                aggregators = self._list_config_aggregators(
                    client,
                    region,
                    warnings,
                )
                conformance_packs = self._list_config_conformance_packs(
                    client,
                    region,
                    warnings,
                )
            except Exception as exc:  # noqa: BLE001
                record_context_warning(context, warnings, region, "AWS Config", exc)
                records.append(
                    RegionalSecurityServiceRecord(
                        service_name="AWS Config",
                        region=region,
                        enabled=None,
                        detail="AWS Config visibility unavailable.",
                    ),
                )
                continue
            recording = any(recording_states) if recorder_names <= status_names else None
            records.append(
                RegionalSecurityServiceRecord(
                    service_name="AWS Config",
                    region=region,
                    enabled=bool(recorders) and recording,
                    detail=(
                        f"{len(recorders)} recorder records visible; "
                        f"recording={recording}; "
                        f"{len(aggregators)} aggregators; "
                        f"{len(conformance_packs)} conformance packs."
                    ),
                    metadata={
                        "recorder_count": len(recorders),
                        "recording": recording,
                        "aggregator_count": len(aggregators),
                        "aggregator_names": tuple(
                            str(aggregator.get("ConfigurationAggregatorName") or "") for aggregator in aggregators[:10] if isinstance(aggregator, dict)
                        ),
                        "conformance_pack_count": len(conformance_packs),
                        "conformance_pack_names": tuple(
                            str(pack.get("ConformancePackName") or "") for pack in conformance_packs[:10] if isinstance(pack, dict)
                        ),
                    },
                ),
            )
        return records

    def _list_config_aggregators(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        aggregators: list[dict[str, Any]] = []
        try:
            response = client.describe_configuration_aggregators()
            aggregators.extend(require_response_rows(response, "ConfigurationAggregators"))
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                f"AWS Config aggregator inventory in {region}",
                exc,
            )
        return aggregators

    def _list_config_conformance_packs(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        packs: list[dict[str, Any]] = []
        try:
            response = client.describe_conformance_packs()
            packs.extend(require_response_rows(response, "ConformancePackDetails"))
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                f"AWS Config conformance pack inventory in {region}",
                exc,
            )
        return packs

    def _collect_guardduty(
        self,
        context: ScannerContext,
        regions: list[str],
        warnings: list[str],
    ) -> list[RegionalSecurityServiceRecord]:
        records: list[RegionalSecurityServiceRecord] = []
        for region in regions:
            client = self._create_client(context, "guardduty", region)
            try:
                response = client.list_detectors()
                detector_ids = require_response_strings(response, "DetectorIds")
                require_complete_response(response)
            except Exception as exc:  # noqa: BLE001
                record_context_warning(context, warnings, region, "GuardDuty", exc)
                records.append(
                    RegionalSecurityServiceRecord(
                        service_name="GuardDuty",
                        region=region,
                        enabled=None,
                        detail="GuardDuty visibility unavailable.",
                    ),
                )
                continue
            records.append(
                RegionalSecurityServiceRecord(
                    service_name="GuardDuty",
                    region=region,
                    enabled=bool(detector_ids),
                    detail=f"{len(detector_ids)} detector records visible.",
                ),
            )
        return records

    def _collect_securityhub(
        self,
        context: ScannerContext,
        regions: list[str],
        warnings: list[str],
    ) -> list[RegionalSecurityServiceRecord]:
        records: list[RegionalSecurityServiceRecord] = []
        for region in regions:
            client = self._create_client(context, "securityhub", region)
            try:
                require_response_mapping(client.describe_hub())
                response = client.get_enabled_standards()
                standards = require_response_rows(response, "StandardsSubscriptions")
                require_complete_response(response)
            except Exception as exc:  # noqa: BLE001
                if aws_errors.is_service_unavailable_error(
                    exc,
                    service_name="securityhub",
                    operation_name="DescribeHub",
                ):
                    enabled = False
                else:
                    record_context_warning(
                        context,
                        warnings,
                        region,
                        "Security Hub",
                        exc,
                    )
                    enabled = None
                records.append(
                    RegionalSecurityServiceRecord(
                        service_name="Security Hub",
                        region=region,
                        enabled=enabled,
                        detail="Security Hub visibility unavailable or not enabled.",
                    ),
                )
                continue
            records.append(
                RegionalSecurityServiceRecord(
                    service_name="Security Hub",
                    region=region,
                    enabled=bool(standards),
                    detail=f"{len(standards)} enabled standards visible.",
                ),
            )
        return records

    def _create_client(
        self,
        context: ScannerContext,
        service_name: str,
        region: str,
    ) -> Any:  # noqa: ANN401
        return context.security.create_client(
            service_name,
            region_name=region,
            collector_name="AwsSecurityServiceCoverageReviewScanner",
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="AwsSecurityServiceCoverageReviewScanner",
            implementation_module="unio_collector.scanners.security_governance.service.coverage.scanner",
        )
