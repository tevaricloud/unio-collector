from __future__ import annotations  # noqa: D100

import logging
from typing import TYPE_CHECKING, Any

from unio_collector.aws.extended_support.helpers import (
    build_ec2_arn,
    chunk_values,
    optional_str,
)
from unio_collector.aws.inventory_helpers import RegionalInventoryCollectionHelper
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.rds import tags_to_dict
from unio_collector.aws.versioned_resource_record import VersionedResourceRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord

LOGGER = logging.getLogger(__name__)


class ExtendedSupportInventoryCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._pagination = AwsPaginationHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="ExtendedSupportInventoryCollector",
        )

    def collect_resources(  # noqa: D102
        self,
        *,
        lambda_function_inventory_by_region: (dict[str, list[LambdaFunctionInventoryRecord]] | None) = None,
    ) -> list[VersionedResourceRecord]:
        return [
            *self.collect_rds_resources(),
            *self.collect_lambda_resources(
                lambda_function_inventory_by_region=(lambda_function_inventory_by_region),
            ),
            *self.collect_ec2_ami_resources(),
            *self.collect_elasticache_resources(),
            *self.collect_opensearch_resources(),
            *self.collect_eks_resources(),
        ]

    def collect_rds_resources(self) -> list[VersionedResourceRecord]:  # noqa: D102
        return self._collect_service_regions(
            service="rds",
            operation="DescribeDBInstances",
            collect_region=self.collect_rds_instances,
        )

    def collect_lambda_resources(  # noqa: D102
        self,
        *,
        lambda_function_inventory_by_region: (dict[str, list[LambdaFunctionInventoryRecord]] | None) = None,
    ) -> list[VersionedResourceRecord]:
        if lambda_function_inventory_by_region is not None:
            return self.build_lambda_resources_from_inventory(
                lambda_function_inventory_by_region,
            )
        return self._collect_service_regions(
            service="lambda",
            operation="ListFunctions",
            collect_region=self.collect_lambda_functions,
        )

    def collect_ec2_ami_resources(self) -> list[VersionedResourceRecord]:  # noqa: D102
        return self._collect_service_regions(
            service="ec2",
            operation="DescribeInstances",
            collect_region=self.collect_ec2_instance_amis,
        )

    def collect_elasticache_resources(self) -> list[VersionedResourceRecord]:  # noqa: D102
        return self._collect_service_regions(
            service="elasticache",
            operation="DescribeCacheClusters",
            collect_region=self.collect_elasticache_clusters,
        )

    def collect_opensearch_resources(self) -> list[VersionedResourceRecord]:  # noqa: D102
        return self._collect_service_regions(
            service="opensearch",
            operation="ListDomainNames",
            collect_region=self.collect_opensearch_domains,
        )

    def collect_eks_resources(self) -> list[VersionedResourceRecord]:  # noqa: D102
        return self._collect_service_regions(
            service="eks",
            operation="ListClusters",
            collect_region=self.collect_eks_clusters,
        )

    def _collect_service_regions(
        self,
        *,
        service: str,
        operation: str,
        collect_region: Callable[[str], list[VersionedResourceRecord]],
    ) -> list[VersionedResourceRecord]:
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(service),
            service=service,
            operation=operation,
            collect_region=collect_region,
        )

    def collect_rds_instances(self, region: str) -> list[VersionedResourceRecord]:  # noqa: D102
        client = self.session.create_client(
            "rds",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[VersionedResourceRecord] = []
        pages = self._pagination.collect_token_pages(
            client,
            "describe_db_instances",
            result_key="DBInstances",
            request_parameters={"MaxRecords": 100},
            request_cursor_key="Marker",
            response_cursor_keys=("Marker",),
        ).pages
        for response in pages:
            for instance in response.get("DBInstances", []):
                arn = instance.get("DBInstanceArn")
                records.append(
                    VersionedResourceRecord(
                        service="Amazon RDS",
                        resource_id=instance.get("DBInstanceIdentifier", "unknown"),
                        resource_name=instance.get("DBInstanceIdentifier"),
                        account_id=self.account_id,
                        region=region,
                        arn=arn,
                        resource_type="RDS instance",
                        engine=instance.get("Engine"),
                        version=instance.get("EngineVersion"),
                        platform=None,
                        tags=self.collect_rds_tags(client, arn),
                        evidence_source="rds:DescribeDBInstances",
                    ),
                )
        return records

    def collect_lambda_functions(self, region: str) -> list[VersionedResourceRecord]:  # noqa: D102
        client = self.session.create_client(
            "lambda",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[VersionedResourceRecord] = []
        pages = self._pagination.collect_token_pages(
            client,
            "list_functions",
            result_key="Functions",
            request_parameters={"MaxItems": 100},
            request_cursor_key="Marker",
            response_cursor_keys=("NextMarker",),
        ).pages
        for response in pages:
            records.extend(self.build_lambda_resource_record(region, function) for function in response.get("Functions", []))
        return records

    def collect_ec2_instance_amis(self, region: str) -> list[VersionedResourceRecord]:  # noqa: D102
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "describe_instances",
            result_key="Reservations",
            request_parameters={"MaxResults": 1000},
        ).pages
        instances = [
            instance
            for page in pages
            for reservation in page.get("Reservations", [])
            if isinstance(reservation, dict)
            for instance in reservation.get("Instances", [])
            if isinstance(instance, dict)
        ]
        images_by_id = self._describe_images_by_id(
            client,
            sorted(
                {str(instance.get("ImageId")) for instance in instances if instance.get("ImageId")},
            ),
        )
        records: list[VersionedResourceRecord] = []
        for instance in instances:
            instance_id = optional_str(instance.get("InstanceId")) or "unknown"
            image_id = optional_str(instance.get("ImageId"))
            image = images_by_id.get(image_id or "", {})
            tags = tags_to_dict(instance.get("Tags", []))
            image_creation = optional_str(image.get("CreationDate"))
            records.append(
                VersionedResourceRecord(
                    service="Amazon EC2",
                    resource_id=instance_id,
                    resource_name=tags.get("Name"),
                    account_id=self.account_id,
                    region=region,
                    arn=build_ec2_arn(region, self.account_id, "instance", instance_id),
                    resource_type="EC2 instance AMI",
                    engine="ami",
                    version=image_id,
                    platform=optional_str(
                        image.get("PlatformDetails") or instance.get("PlatformDetails") or instance.get("Platform"),
                    ),
                    tags=tags,
                    evidence_source="ec2:DescribeInstances/ec2:DescribeImages",
                    attributes={
                        "ami_id": image_id,
                        "ami_name": optional_str(image.get("Name")),
                        "ami_creation_date": image_creation,
                        "instance_state": (instance.get("State", {}).get("Name") if isinstance(instance.get("State"), dict) else instance.get("State")),
                    },
                ),
            )
        return records

    def collect_elasticache_clusters(  # noqa: D102
        self,
        region: str,
    ) -> list[VersionedResourceRecord]:
        client = self.session.create_client(
            "elasticache",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "describe_cache_clusters",
            result_key="CacheClusters",
            request_parameters={"MaxRecords": 100, "ShowCacheNodeInfo": False},
            request_cursor_key="Marker",
            response_cursor_keys=("Marker",),
        ).pages
        records: list[VersionedResourceRecord] = []
        for response in pages:
            for cluster in response.get("CacheClusters", []):
                cluster_id = optional_str(cluster.get("CacheClusterId")) or "unknown"
                engine = optional_str(cluster.get("Engine"))
                version = optional_str(cluster.get("EngineVersion"))
                records.append(
                    VersionedResourceRecord(
                        service="Amazon ElastiCache",
                        resource_id=cluster_id,
                        resource_name=cluster_id,
                        account_id=self.account_id,
                        region=region,
                        arn=optional_str(cluster.get("ARN")),
                        resource_type="ElastiCache cluster",
                        engine=engine,
                        version=version,
                        platform=engine,
                        tags={},
                        evidence_source="elasticache:DescribeCacheClusters",
                    ),
                )
        return records

    def collect_opensearch_domains(  # noqa: D102
        self,
        region: str,
    ) -> list[VersionedResourceRecord]:
        client = self.session.create_client(
            "opensearch",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "list_domain_names",
            result_key="DomainNames",
        ).pages
        names = [str(item.get("DomainName")) for page in pages for item in page.get("DomainNames", []) if isinstance(item, dict) and item.get("DomainName")]
        records: list[VersionedResourceRecord] = []
        for batch in chunk_values(names, 5):
            response = client.describe_domains(DomainNames=batch)
            for domain in response.get("DomainStatusList", []):
                name = optional_str(domain.get("DomainName")) or "unknown"
                version = optional_str(domain.get("EngineVersion"))
                records.append(
                    VersionedResourceRecord(
                        service="Amazon OpenSearch Service",
                        resource_id=name,
                        resource_name=name,
                        account_id=self.account_id,
                        region=region,
                        arn=optional_str(domain.get("ARN")),
                        resource_type="OpenSearch domain",
                        engine="opensearch",
                        version=version,
                        platform="OpenSearch",
                        tags={},
                        evidence_source="opensearch:ListDomainNames/opensearch:DescribeDomains",
                    ),
                )
        return records

    def collect_eks_clusters(self, region: str) -> list[VersionedResourceRecord]:  # noqa: D102
        client = self.session.create_client(
            "eks",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "list_clusters",
            result_key="clusters",
        ).pages
        names = [str(name) for page in pages for name in page.get("clusters", []) if name]
        records: list[VersionedResourceRecord] = []
        for name in names:
            cluster = client.describe_cluster(name=name).get("cluster", {})
            records.append(
                VersionedResourceRecord(
                    service="Amazon EKS",
                    resource_id=name,
                    resource_name=name,
                    account_id=self.account_id,
                    region=region,
                    arn=optional_str(cluster.get("arn")),
                    resource_type="EKS cluster",
                    engine="kubernetes",
                    version=optional_str(cluster.get("version")),
                    platform="Kubernetes",
                    tags={str(key): str(value) for key, value in (cluster.get("tags") or {}).items()},
                    evidence_source="eks:ListClusters/eks:DescribeCluster",
                ),
            )
        return records

    def _describe_images_by_id(
        self,
        client: Any,  # noqa: ANN401
        image_ids: list[str],
    ) -> dict[str, dict[str, Any]]:
        if not image_ids:
            return {}
        images: dict[str, dict[str, Any]] = {}
        for batch in chunk_values(image_ids, 100):
            try:
                response = client.describe_images(ImageIds=batch)
            except Exception as exc:
                LOGGER.debug(
                    "Skipping EC2 image metadata batch after describe_images failure.",
                    exc_info=exc,
                )
                continue
            for image in response.get("Images", []):
                image_id = image.get("ImageId")
                if image_id:
                    images[str(image_id)] = image
        return images

    def build_lambda_resources_from_inventory(  # noqa: D102
        self,
        records_by_region: dict[str, list[LambdaFunctionInventoryRecord]],
    ) -> list[VersionedResourceRecord]:
        resources: list[VersionedResourceRecord] = []
        for region in self.get_available_regions("lambda"):
            resources.extend(self.build_lambda_resource_record(region, record.function) for record in records_by_region.get(region, []))
        return resources

    def build_lambda_resource_record(  # noqa: D102
        self,
        region: str,
        function: dict[str, object],
    ) -> VersionedResourceRecord:
        return VersionedResourceRecord(
            service="AWS Lambda",
            resource_id=str(function.get("FunctionArn") or "unknown"),
            resource_name=optional_str(function.get("FunctionName")),
            account_id=self.account_id,
            region=region,
            arn=optional_str(function.get("FunctionArn")),
            resource_type="Lambda function",
            engine=optional_str(function.get("Runtime")),
            version=optional_str(function.get("Runtime")),
            platform="Lambda runtime",
            tags={},
            evidence_source="lambda:ListFunctions",
        )

    def collect_rds_tags(self, client: Any, arn: str | None) -> dict[str, str]:  # noqa: ANN401, D102
        if not arn:
            return {}
        try:
            response = client.list_tags_for_resource(ResourceName=arn)
        except Exception:  # noqa: BLE001
            return {}
        return tags_to_dict(response.get("TagList", []))

    def get_available_regions(self, service_name: str) -> list[str]:  # noqa: D102
        if self.selected_regions:
            return sorted(self.selected_regions)
        return sorted(self.session.get_available_regions(service_name))
