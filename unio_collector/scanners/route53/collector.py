from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.service.coverage.collector import ServiceCoverageCollector
from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class Route53CostGovernanceReviewCollector(ServiceCoverageCollector):
    """Collect service evidence independently of private finding interpretation."""

    collector_name = "Route53CostGovernanceCollector"

    def collect(self, context: ScannerContext) -> ServiceCoverageEvidence:  # noqa: D102
        client = self.create_client(context, "route53", "us-east-1")
        records: list[ServiceCoverageRecord] = []
        warnings: list[str] = []
        try:
            zones = self.collect_items(client, "list_hosted_zones", "HostedZones")
            records.extend(self._build_zone_records(zones))
            checks = self.collect_items(client, "list_health_checks", "HealthChecks")
            records.extend(self._build_health_check_records(checks))
            policies = self.collect_items(
                client,
                "list_traffic_policies",
                "TrafficPolicySummaries",
            )
            records.extend(self._build_traffic_policy_records(policies))
        except Exception as exc:  # noqa: BLE001
            self.add_warning(context, warnings, "Route 53", "global", exc)
        return ServiceCoverageEvidence(
            records=records,
            regions=["global"],
            warnings=warnings,
            account_id=context.security.account_id,
            metadata={
                "hosted_zone_count": sum(1 for record in records if record.resource_type == "Hosted zone"),
                "health_check_count": sum(1 for record in records if record.resource_type == "Health check"),
                "traffic_policy_count": sum(1 for record in records if record.resource_type == "Traffic policy"),
            },
        )

    def _build_zone_records(
        self,
        zones: list[dict[str, Any]],
    ) -> list[ServiceCoverageRecord]:
        return [
            ServiceCoverageRecord(
                service="Amazon Route 53",
                region="global",
                resource_type="Hosted zone",
                resource_id=str(zone.get("Id") or ""),
                resource_name=str(zone.get("Name") or ""),
                attributes={
                    "record_set_count": zone.get("ResourceRecordSetCount"),
                    "private_zone": self._private_zone(zone),
                },
            )
            for zone in zones
        ]

    def _private_zone(self, zone: dict[str, Any]) -> bool | None:
        config = zone.get("Config")
        value = config.get("PrivateZone") if isinstance(config, dict) else None
        return value if isinstance(value, bool) else None

    def _build_health_check_records(
        self,
        checks: list[dict[str, Any]],
    ) -> list[ServiceCoverageRecord]:
        return [
            ServiceCoverageRecord(
                service="Amazon Route 53",
                region="global",
                resource_type="Health check",
                resource_id=str(check.get("Id") or ""),
                resource_name=str(check.get("CallerReference") or ""),
                attributes={
                    "health_check_type": (check.get("HealthCheckConfig") or {}).get(
                        "Type",
                    ),
                },
            )
            for check in checks
        ]

    def _build_traffic_policy_records(
        self,
        policies: list[dict[str, Any]],
    ) -> list[ServiceCoverageRecord]:
        return [
            ServiceCoverageRecord(
                service="Amazon Route 53",
                region="global",
                resource_type="Traffic policy",
                resource_id=str(policy.get("Id") or ""),
                resource_name=str(policy.get("Name") or ""),
                attributes={"traffic_policy_type": policy.get("Type")},
            )
            for policy in policies
        ]

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="Route53CostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.route53.cost_governance",
        )
