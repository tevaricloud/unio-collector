from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import (
    ProviderResponseError,
    require_complete_response,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)
from unio_collector.scanners.audit_cost.cloudtrail.facts import dedupe_cloudtrail_security_trails
from unio_collector.scanners.audit_cost.cloudtrail.security.evidence import (
    CloudTrailSecurityPostureEvidence,
)
from unio_collector.scanners.audit_cost.cloudtrail.trail_record import (
    CloudTrailSecurityTrailRecord,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class CloudTrailSecurityPostureReviewCollector(BaseUnioScanner):
    """Collect provider evidence for cloudtrail-security-posture-review."""

    def collect(self, context: ScannerContext) -> CloudTrailSecurityPostureEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "cloudtrail")
        warnings: list[str] = []
        trails: list[CloudTrailSecurityTrailRecord] = []
        inventory_states: list[bool] = []
        for region in regions:
            client = context.security.create_client(
                "cloudtrail",
                region_name=region,
                collector_name="CloudTrailSecurityPostureReviewScanner",
            )
            trails.extend(self._collect_region_trails(client, region, warnings, inventory_states))
        for warning in warnings:
            context.warnings.add(warning)
        return CloudTrailSecurityPostureEvidence(
            trails=tuple(dedupe_cloudtrail_security_trails(trails)),
            regions=tuple(regions),
            warnings=tuple(warnings),
            account_id=context.security.account_id,
            trail_inventory_complete=bool(regions) and all(inventory_states),
        )

    def _collect_region_trails(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
        inventory_states: list[bool] | None = None,
    ) -> list[CloudTrailSecurityTrailRecord]:
        raw_trails: list[dict[str, Any]] = []
        complete = False
        try:
            response = client.describe_trails(includeShadowTrails=True)
            raw_trails.extend(require_response_rows(response, "trailList"))
            require_complete_response(response)
            complete = True
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"CloudTrail trails in {region}", exc)
        records: list[CloudTrailSecurityTrailRecord] = []
        for trail in raw_trails:
            try:
                name = require_response_string(trail.get("Name") or trail.get("TrailARN"))
            except ProviderResponseError as exc:
                complete = False
                append_warning(warnings, f"CloudTrail trail identity in {region}", exc)
                continue
            status = self._get_trail_status(client, name, warnings)
            event_selectors = self._get_event_selectors(client, name, warnings)
            records.append(
                CloudTrailSecurityTrailRecord(
                    name=name,
                    arn=trail.get("TrailARN"),
                    home_region=trail.get("HomeRegion"),
                    region=region,
                    is_multi_region=self._observed_flag(trail, "IsMultiRegionTrail", name, warnings),
                    is_organization_trail=self._observed_flag(trail, "IsOrganizationTrail", name, warnings),
                    log_file_validation_enabled=self._observed_flag(trail, "LogFileValidationEnabled", name, warnings),
                    is_logging=status,
                    management_events_enabled=(event_selectors["management_events_enabled"]),
                    read_write_type=event_selectors["read_write_type"],
                    s3_bucket_name=trail.get("S3BucketName"),
                    kms_key_id=trail.get("KmsKeyId"),
                ),
            )
        if inventory_states is not None:
            inventory_states.append(complete)
        return records

    def _observed_flag(self, response: dict[str, Any], key: str, trail_name: str, warnings: list[str]) -> bool | None:
        try:
            return require_response_bool(response.get(key))
        except ProviderResponseError as exc:
            append_warning(warnings, f"CloudTrail {key} for {trail_name}", exc)
            return None

    def _get_trail_status(
        self,
        client: Any,  # noqa: ANN401
        trail_name: str,
        warnings: list[str],
    ) -> bool | None:
        try:
            response = require_response_mapping(client.get_trail_status(Name=trail_name))
            logging = require_response_bool(response.get("IsLogging"))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"CloudTrail status for {trail_name}", exc)
            return None
        return logging

    def _get_event_selectors(
        self,
        client: Any,  # noqa: ANN401
        trail_name: str,
        warnings: list[str],
    ) -> dict[str, Any]:
        try:
            response = require_response_mapping(client.get_event_selectors(TrailName=trail_name))
            if "EventSelectors" not in response and "AdvancedEventSelectors" in response:
                require_response_rows(response, "AdvancedEventSelectors")
                warnings.append(f"CloudTrail event selectors for {trail_name}: advanced selector coverage is unavailable.")
                return {"management_events_enabled": None, "read_write_type": None}
            selectors = require_response_rows(response, "EventSelectors")
            states = [require_response_bool(selector.get("IncludeManagementEvents")) for selector in selectors]
            read_write_types = {require_response_string(selector.get("ReadWriteType")) for selector in selectors}
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                f"CloudTrail event selectors for {trail_name}",
                exc,
            )
            return {"management_events_enabled": None, "read_write_type": None}
        if not selectors:
            return {"management_events_enabled": None, "read_write_type": None}
        return {
            "management_events_enabled": any(states),
            "read_write_type": ", ".join(sorted(read_write_types)) or None,
        }

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudTrailSecurityPostureReviewScanner",
            implementation_module="unio_collector.scanners.audit_cost.cloudtrail.security.scanner",
        )
