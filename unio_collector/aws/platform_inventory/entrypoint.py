from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.api_gateway.region_record import ApiGatewayRegionRecord
    from unio_collector.aws.ecs.region_record import EcsRegionRecord
    from unio_collector.aws.eks.region_record import EksRegionRecord
    from unio_collector.aws.elasticache.region_record import ElastiCacheRegionRecord
    from unio_collector.aws.opensearch.region_record import OpenSearchRegionRecord
    from unio_collector.aws.redshift.region_record import RedshiftRegionRecord
    from unio_collector.core.scan.period import ScanPeriod


class ManagedPlatformInventoryEntrypointMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def collect_api_gateway_records(self) -> list[ApiGatewayRegionRecord]:  # noqa: D102
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="apigateway",
            operation=self._collector._build_api_gateway_collection_operation_label(),  # noqa: SLF001
            collect_region=self._collector._collect_api_gateway_record,  # noqa: SLF001
        )

    def collect_eks_records(self) -> list[EksRegionRecord]:  # noqa: D102
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="eks",
            operation="ListClusters+DescribeCluster+ListNodegroups+ListFargateProfiles",
            collect_region=self._collector._collect_eks_record,  # noqa: SLF001
        )

    def collect_ecs_records(self) -> list[EcsRegionRecord]:  # noqa: D102
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="ecs",
            operation=self._collector._build_ecs_collection_operation_label(),  # noqa: SLF001
            collect_region=self._collector._collect_ecs_record,  # noqa: SLF001
        )

    def collect_opensearch_records(self) -> list[OpenSearchRegionRecord]:  # noqa: D102
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="opensearch",
            operation="ListDomainNames+DescribeDomains",
            collect_region=self._collector._collect_opensearch_record,  # noqa: SLF001
        )

    def collect_redshift_records(self) -> list[RedshiftRegionRecord]:  # noqa: D102
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="redshift",
            operation="DescribeClusters+ListWorkgroups+ListNamespaces",
            collect_region=self._collector._collect_redshift_record,  # noqa: SLF001
        )

    def collect_elasticache_records(  # noqa: D102
        self,
        scan_period: ScanPeriod | None = None,
    ) -> list[ElastiCacheRegionRecord]:
        return self._collector._regional_collection.collect_region_records(  # noqa: SLF001
            regions=self._collector.get_available_regions(),
            service="elasticache",
            operation=self._collector._build_elasticache_collection_operation_label(),  # noqa: SLF001
            collect_region=lambda region: self._collector._collect_elasticache_record(  # noqa: SLF001
                region,
                scan_period,
            ),
        )

    def _build_api_gateway_collection_operation_label(self) -> str:
        operations = [
            "GetRestApis",
            "GetStages",
            "GetApis",
            "GetRoutes",
        ]
        if self._collector.api_gateway_vpc_link_detail_mode == "full":
            operations.append("GetVpcLinks")
        return "+".join(operations)

    def _build_ecs_collection_operation_label(self) -> str:
        operations = [
            "ListClusters",
            "DescribeClusters",
            "ListServices",
            "DescribeServices",
        ]
        if self._collector.ecs_task_definition_detail_mode == "full":
            operations.append("DescribeTaskDefinition")
        return "+".join(operations)

    def _build_elasticache_collection_operation_label(self) -> str:
        operations = [
            "DescribeCacheClusters",
            "DescribeReplicationGroups",
        ]
        if self._collector.elasticache_metric_detail_mode == "full":
            operations.append("CloudWatchMetricContext")
        return "+".join(operations)
