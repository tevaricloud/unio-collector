from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning
from unio_collector.scanners.security_governance.public_exposure.evidence import (
    PublicServiceExposureEvidence,
)
from unio_collector.scanners.security_governance.public_exposure.record import (
    PublicServiceExposureRecord,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class PublicServiceExposureReviewCollector(BaseUnioScanner):
    """Collect provider evidence for public-service-exposure-review."""

    def collect(self, context: ScannerContext) -> PublicServiceExposureEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "ec2")
        warnings: list[str] = []
        records: list[PublicServiceExposureRecord] = []
        for region in regions:
            records.extend(self._collect_rds(context, region, warnings))
            records.extend(self._collect_opensearch(context, region, warnings))
            records.extend(self._collect_redshift(context, region, warnings))
            records.extend(self._collect_load_balancers(context, region, warnings))
            records.extend(self._collect_api_gateway(context, region, warnings))
        global_records = self._collect_cloudfront(context, warnings)
        for warning in warnings:
            context.warnings.add(warning)
        return PublicServiceExposureEvidence(
            records=tuple(records),
            global_records=tuple(global_records),
            regions=tuple(regions),
            warnings=tuple(warnings),
        )

    def _collect_rds(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "rds",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.describe_db_instances()
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"RDS public exposure in {region}", exc)
            return []
        instances = response.get("DBInstances", [])
        records: list[PublicServiceExposureRecord] = []
        if not isinstance(instances, list):
            return records
        for instance in instances:
            if not isinstance(instance, dict) or not instance.get("PubliclyAccessible"):
                continue
            resource_id = str(instance.get("DBInstanceIdentifier") or "unknown-rds")
            records.append(
                PublicServiceExposureRecord(
                    service_name="Amazon RDS",
                    region=region,
                    resource_type="RDS DB instance",
                    resource_id=resource_id,
                    resource_name=resource_id,
                    arn=str(instance.get("DBInstanceArn") or ""),
                    exposure_type="publicly_accessible",
                    confidence="high",
                    detail="RDS returned PubliclyAccessible=true.",
                ),
            )
        return records

    def _collect_opensearch(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "es",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            domains = client.list_domain_names().get("DomainNames", [])
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"OpenSearch public exposure in {region}", exc)
            return []
        records: list[PublicServiceExposureRecord] = []
        if not isinstance(domains, list):
            return records
        for domain in domains[:50]:
            if not isinstance(domain, dict):
                continue
            name = str(domain.get("DomainName") or "")
            if not name:
                continue
            try:
                detail = client.describe_domain_config(DomainName=name)
            except Exception as exc:  # noqa: BLE001
                append_warning(warnings, f"OpenSearch domain {name} in {region}", exc)
                continue
            config = detail.get("DomainConfig", {})
            vpc = config.get("VPCOptions", {}) if isinstance(config, dict) else {}
            options = vpc.get("Options", {}) if isinstance(vpc, dict) else {}
            if isinstance(options, dict) and options.get("VPCId"):
                continue
            records.append(
                PublicServiceExposureRecord(
                    service_name="Amazon OpenSearch Service",
                    region=region,
                    resource_type="OpenSearch domain",
                    resource_id=name,
                    resource_name=name,
                    exposure_type="public_endpoint_review",
                    confidence="medium",
                    detail=("OpenSearch domain did not show VPCOptions VPCId in DescribeDomainConfig."),
                ),
            )
        return records

    def _collect_redshift(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "redshift",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.describe_clusters()
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"Redshift public exposure in {region}", exc)
            return []
        clusters = response.get("Clusters", [])
        if not isinstance(clusters, list):
            return []
        records: list[PublicServiceExposureRecord] = []
        for cluster in clusters:
            if not isinstance(cluster, dict) or not cluster.get("PubliclyAccessible"):
                continue
            resource_id = str(cluster.get("ClusterIdentifier") or "unknown-redshift")
            records.append(
                PublicServiceExposureRecord(
                    service_name="Amazon Redshift",
                    region=region,
                    resource_type="Redshift cluster",
                    resource_id=resource_id,
                    resource_name=resource_id,
                    exposure_type="publicly_accessible",
                    confidence="high",
                    detail="Redshift returned PubliclyAccessible=true.",
                ),
            )
        return records

    def _collect_load_balancers(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "elbv2",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.describe_load_balancers()
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"Load balancer exposure in {region}", exc)
            return []
        balancers = response.get("LoadBalancers", [])
        if not isinstance(balancers, list):
            return []
        records: list[PublicServiceExposureRecord] = []
        for balancer in balancers:
            if not isinstance(balancer, dict) or balancer.get("Scheme") != "internet-facing":
                continue
            resource_id = str(
                balancer.get("LoadBalancerArn") or balancer.get("LoadBalancerName") or "unknown-load-balancer",
            )
            records.append(
                PublicServiceExposureRecord(
                    service_name="Elastic Load Balancing",
                    region=region,
                    resource_type="Application or Network Load Balancer",
                    resource_id=resource_id,
                    resource_name=str(balancer.get("LoadBalancerName") or ""),
                    arn=str(balancer.get("LoadBalancerArn") or ""),
                    exposure_type="internet_facing",
                    confidence="medium",
                    detail=("Load balancer scheme is internet-facing; validate expected public exposure and listener controls."),
                    metadata={"type": balancer.get("Type")},
                ),
            )
        return records

    def _collect_api_gateway(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        records: list[PublicServiceExposureRecord] = []
        records.extend(self._collect_rest_apis(context, region, warnings))
        records.extend(self._collect_http_apis(context, region, warnings))
        return records

    def _collect_rest_apis(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "apigateway",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.get_rest_apis(limit=100)
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"API Gateway REST exposure in {region}", exc)
            return []
        items = response.get("items", [])
        if not isinstance(items, list):
            return []
        records: list[PublicServiceExposureRecord] = []
        for api in items:
            if not isinstance(api, dict):
                continue
            endpoint_config = api.get("endpointConfiguration", {})
            types = endpoint_config.get("types", []) if isinstance(endpoint_config, dict) else []
            if "PRIVATE" in types:
                continue
            api_id = str(api.get("id") or "unknown-rest-api")
            records.append(
                PublicServiceExposureRecord(
                    service_name="Amazon API Gateway",
                    region=region,
                    resource_type="API Gateway REST API",
                    resource_id=api_id,
                    resource_name=str(api.get("name") or ""),
                    exposure_type="public_endpoint_review",
                    confidence="medium",
                    detail=("REST API endpoint type is not PRIVATE; validate public access policy, authorizers, and intended exposure."),
                    metadata={"endpoint_types": tuple(str(item) for item in types)},
                ),
            )
        return records

    def _collect_http_apis(
        self,
        context: ScannerContext,
        region: str,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "apigatewayv2",
            region_name=region,
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.get_apis(MaxResults="100")
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"API Gateway v2 exposure in {region}", exc)
            return []
        items = response.get("Items", [])
        if not isinstance(items, list):
            return []
        return [
            PublicServiceExposureRecord(
                service_name="Amazon API Gateway",
                region=region,
                resource_type="API Gateway HTTP/WebSocket API",
                resource_id=str(api.get("ApiId") or "unknown-api"),
                resource_name=str(api.get("Name") or ""),
                exposure_type="public_endpoint_review",
                confidence="medium",
                detail=("API Gateway v2 API is externally addressable unless fronted by private network controls; validate intended exposure."),
                metadata={"protocol_type": api.get("ProtocolType")},
            )
            for api in items
            if isinstance(api, dict)
        ]

    def _collect_cloudfront(
        self,
        context: ScannerContext,
        warnings: list[str],
    ) -> list[PublicServiceExposureRecord]:
        client = context.security.create_client(
            "cloudfront",
            region_name="us-east-1",
            collector_name="PublicServiceExposureReviewScanner",
        )
        try:
            response = client.list_distributions()
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "CloudFront origin exposure", exc)
            return []
        distribution_list = response.get("DistributionList", {})
        items = distribution_list.get("Items", []) if isinstance(distribution_list, dict) else []
        if not isinstance(items, list):
            return []
        records: list[PublicServiceExposureRecord] = []
        for distribution in items[:100]:
            if not isinstance(distribution, dict):
                continue
            dist_id = str(distribution.get("Id") or "unknown-distribution")
            origins = distribution.get("Origins", {})
            origin_items = origins.get("Items", []) if isinstance(origins, dict) else []
            if not isinstance(origin_items, list):
                continue
            for origin in origin_items:
                if not isinstance(origin, dict):
                    continue
                domain_name = str(origin.get("DomainName") or "")
                if not domain_name:
                    continue
                records.append(
                    PublicServiceExposureRecord(
                        service_name="Amazon CloudFront",
                        region="global",
                        resource_type="CloudFront origin",
                        resource_id=f"{dist_id}:{domain_name}",
                        resource_name=domain_name,
                        exposure_type="origin_exposure_review",
                        confidence="medium",
                        detail=(
                            "CloudFront origin is visible in distribution "
                            "configuration; validate origin access controls and "
                            "whether direct origin access is blocked."
                        ),
                        metadata={"distribution_id": dist_id},
                    ),
                )
        return records

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="PublicServiceExposureReviewScanner",
            implementation_module="unio_collector.scanners.security_governance.public_exposure.scanner",
        )
