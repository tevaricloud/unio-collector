from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from boto3.session import Session as Boto3Session

from unio_collector.aws.response_admission import ProviderResponseError, require_response_rows, response_cursor
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.service.coverage.collector import ServiceCoverageCollector
from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
from unio_collector.scanners.service.coverage.helpers import count_records
from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class LightsailCostGovernanceReviewCollector(ServiceCoverageCollector):
    """Collect service evidence independently of private finding interpretation."""

    collector_name = "LightsailCostGovernanceCollector"

    service_name = "lightsail"

    operation_names = (
        "GetInstances",
        "GetStaticIps",
        "GetDisks",
        "GetLoadBalancers",
        "GetRelationalDatabases",
        "GetBuckets",
        "GetContainerServices",
    )

    def collect(self, context: ScannerContext) -> ServiceCoverageEvidence:  # noqa: D102
        records: list[ServiceCoverageRecord] = []
        warnings: list[str] = []
        regions = self._get_operation_supported_regions(context)
        for region in regions:
            client = self.create_client(context, "lightsail", region)
            try:
                records.extend(self._collect_region(client, region))
            except Exception as exc:  # noqa: BLE001
                self.add_warning(context, warnings, "Lightsail", region, exc)
        return ServiceCoverageEvidence(
            records=records,
            regions=regions,
            warnings=warnings,
            account_id=context.security.account_id,
            metadata={
                "endpoint_strategy": self._endpoint_strategy(context),
                "operation_names": list(self.operation_names),
                "instance_count": count_records(records, "Instance"),
                "static_ip_count": count_records(records, "Static IP"),
                "disk_count": count_records(records, "Disk"),
                "database_count": count_records(records, "Database"),
                "load_balancer_count": count_records(records, "Load balancer"),
                "bucket_count": count_records(records, "Bucket"),
                "container_service_count": count_records(
                    records,
                    "Container service",
                ),
            },
        )

    def _get_operation_supported_regions(self, context: ScannerContext) -> list[str]:
        selected = context.options.get_selected_regions()
        requested = sorted(selected) if selected else self.get_regions(context)
        supported = set(self._get_sdk_lightsail_regions())
        if context.options.has_explicit_region_scope():
            return requested
        regions = [region for region in requested if region in supported]
        excluded = [region for region in requested if region not in supported]
        if excluded:
            context.warnings.add_coverage_note(
                {
                    "type": "service_region_capability",
                    "service": "lightsail",
                    "status": "unsupported_region_excluded",
                    "excluded_regions": excluded,
                    "operation_names": list(self.operation_names),
                    "reason": ("Installed botocore endpoint metadata does not advertise Lightsail endpoints for these regions."),
                },
            )
        return regions

    def _endpoint_strategy(self, context: ScannerContext) -> str:
        if context.options.has_explicit_region_scope():
            return "explicit_region_override"
        return "botocore_lightsail_endpoint_metadata"

    def _get_sdk_lightsail_regions(self) -> list[str]:
        return sorted(Boto3Session().get_available_regions(self.service_name))

    def _collect_region(
        self,
        client: Any,  # noqa: ANN401
        region: str,
    ) -> list[ServiceCoverageRecord]:
        records: list[ServiceCoverageRecord] = []
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_instances",
                "instances",
                "Instance",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_static_ips",
                "staticIps",
                "Static IP",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_disks",
                "disks",
                "Disk",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_load_balancers",
                "loadBalancers",
                "Load balancer",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_relational_databases",
                "relationalDatabases",
                "Database",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_buckets",
                "buckets",
                "Bucket",
            ),
        )
        records.extend(
            self._build_lightsail_records(
                client,
                region,
                "get_container_services",
                "containerServices",
                "Container service",
            ),
        )
        return records

    def _build_lightsail_records(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        operation_name: str,
        result_key: str,
        resource_type: str,
    ) -> list[ServiceCoverageRecord]:
        records: list[ServiceCoverageRecord] = []
        for item in self._collect_lightsail_items(client, operation_name, result_key):
            tags = {str(tag.get("key")): str(tag.get("value") or "") for tag in item.get("tags", []) if isinstance(tag, dict) and tag.get("key")}
            records.append(
                ServiceCoverageRecord(
                    service="Amazon Lightsail",
                    region=region,
                    resource_type=resource_type,
                    resource_id=str(item.get("arn") or item.get("name") or ""),
                    resource_name=str(item.get("name") or ""),
                    arn=str(item.get("arn") or "") or None,
                    tags=tags,
                    attributes={
                        "state": (item.get("state", {}).get("name") if isinstance(item.get("state"), dict) else item.get("state")),
                        "attached": item.get("isAttached"),
                        "attached_to": item.get("attachedTo"),
                        "blueprint_id": item.get("blueprintId"),
                        "bundle_id": item.get("bundleId"),
                    },
                ),
            )
        return records

    def _collect_lightsail_items(
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        result_key: str,
    ) -> list[dict[str, Any]]:
        operation = getattr(client, operation_name)
        items: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            kwargs = {"pageToken": token} if token else {}
            response = operation(**kwargs)
            items.extend(require_response_rows(response, result_key))
            token = response_cursor(response, ("nextPageToken",))
            if not token:
                break
            if token in seen_tokens:
                reason = "RepeatedCursor"
                raise ProviderResponseError(reason)
            seen_tokens.add(token)
        return items

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="LightsailCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.lightsail.cost_governance",
        )
