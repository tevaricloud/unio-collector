"""Account-aware AWS region scoping for scanner execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from unio_collector.aws.audit import AwsAuditContext
from unio_collector.runtime_diagnostics.exception_record import sanitize_diagnostic_text
from unio_collector.scan_workflow.region_models import AwsRegionAvailability

SHARED_REGION_DISCOVERY_SCANNER_ID = "unio-collector-shared-region-discovery"
SHARED_REGION_DISCOVERY_COLLECTOR = "AwsAccountRegionScope"
ENABLED_REGION_OPT_IN_STATUSES = {"opt-in-not-required", "opted-in"}


@dataclass
class AwsRegionScope:
    """Resolve account-enabled AWS regions for scanner collection."""

    session: Any
    account_id: str
    explicit_regions: list[str] | None = None
    home_region: str = "us-east-1"
    _availability: list[AwsRegionAvailability] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _discovery_status: str = field(default="not_started", init=False)
    _discovery_error: str | None = field(default=None, init=False)

    def get_selected_regions(self) -> list[str]:
        """Return explicit regions or account-enabled default regions."""
        if self.explicit_regions:
            return sorted(dict.fromkeys(str(region) for region in self.explicit_regions))
        return self.get_enabled_regions()

    def get_service_regions(self, service_name: str) -> list[str]:
        """Return regions where the account and service are both available."""
        if self.explicit_regions:
            return self.get_selected_regions()
        enabled = set(self.get_enabled_regions())
        if not enabled:
            return []
        get_sdk_available_regions = getattr(
            self.session,
            "get_sdk_available_regions",
            self.session.get_available_regions,
        )
        service_regions = sorted(str(region) for region in get_sdk_available_regions(service_name))
        if not service_regions:
            return sorted(enabled)
        return sorted(region for region in service_regions if region in enabled)

    def get_enabled_regions(self) -> list[str]:
        """Return discovered account-enabled regions."""
        return sorted(region.region_name for region in self._discover() if region.status == "enabled")

    def convert_to_summary(self) -> dict[str, Any]:
        """Return bundle-safe region-scope metadata."""
        if self.explicit_regions:
            selected = self.get_selected_regions()
            return {
                "scope_version": "2026-07",
                "selection_mode": "explicit",
                "explicit_region_scope": True,
                "discovery_status": "explicit_override",
                "selected_regions": selected,
                "enabled_regions": selected,
                "excluded_regions": [],
                "excluded_region_count": 0,
                "limitations": [
                    "An explicit region override was supplied; Unio Collector attempted the requested regions without account opt-in filtering.",
                ],
                "shared_region_discovery_scanner_id": SHARED_REGION_DISCOVERY_SCANNER_ID,
            }
        availability = self._discover()
        enabled = [region for region in availability if region.status == "enabled"]
        excluded = [region for region in availability if region.status != "enabled"]
        limitations = (
            [
                (
                    "Regional AWS collection was limited to account-enabled regions; "
                    "regions that were disabled, not opted in, unsupported, or unknown were excluded."
                ),
            ]
            if excluded
            else []
        )
        if self._discovery_error:
            limitations.append(
                "AWS account region discovery was unavailable; regional scanner coverage is limited.",
            )
        return {
            "scope_version": "2026-07",
            "selection_mode": ("explicit" if self.explicit_regions else "account_enabled"),
            "explicit_region_scope": bool(self.explicit_regions),
            "discovery_status": self._discovery_status,
            "selected_regions": self.get_selected_regions(),
            "enabled_regions": [region.region_name for region in enabled],
            "excluded_regions": [region.convert_to_dict() for region in excluded],
            "excluded_region_count": len(excluded),
            "limitations": limitations,
            "shared_region_discovery_scanner_id": SHARED_REGION_DISCOVERY_SCANNER_ID,
        }

    def _discover(self) -> list[AwsRegionAvailability]:
        if self._availability is not None:
            return self._availability
        if self.explicit_regions:
            self._discovery_status = "explicit_override"
            self._availability = [
                AwsRegionAvailability(
                    region_name=str(region),
                    opt_in_status="explicit",
                    status="explicit",
                    reason="explicit_region_override",
                )
                for region in self.explicit_regions
            ]
            return self._availability
        try:
            client = self.session.create_client(
                "ec2",
                region_name=self.home_region,
                audit_context=self._build_audit_context(),
            )
            response = client.describe_regions(AllRegions=True)
            self._availability = [self._build_availability(region) for region in response.get("Regions", []) if isinstance(region, dict)]
            self._discovery_status = "succeeded"
        except Exception as exc:  # noqa: BLE001
            self._discovery_status = "unavailable"
            self._discovery_error = sanitize_diagnostic_text(exc)
            self._availability = []
        return self._availability

    def _build_audit_context(self) -> AwsAuditContext:
        return AwsAuditContext(
            scanner_id=SHARED_REGION_DISCOVERY_SCANNER_ID,
            collector=SHARED_REGION_DISCOVERY_COLLECTOR,
            allowed_api_calls=("ec2:DescribeRegions",),
            recipient_account_id=self.account_id,
        )

    def _build_availability(self, payload: dict[str, Any]) -> AwsRegionAvailability:
        region_name = str(payload.get("RegionName") or "")
        opt_in_status = str(payload.get("OptInStatus") or "opt-in-not-required")
        if opt_in_status in ENABLED_REGION_OPT_IN_STATUSES:
            return AwsRegionAvailability(
                region_name=region_name,
                opt_in_status=opt_in_status,
                status="enabled",
            )
        return AwsRegionAvailability(
            region_name=region_name,
            opt_in_status=opt_in_status,
            status="excluded",
            reason="account_region_not_enabled",
        )
