from __future__ import annotations  # noqa: D104

from typing import TypeVar

from unio_collector.aws.platform_inventory import (
    ApiGatewayRegionRecord,
    EcsRegionRecord,
    EksRegionRecord,
    ElastiCacheRegionRecord,
    OpenSearchRegionRecord,
    RedshiftRegionRecord,
)

PLATFORM_COST_EXPLORER_SERVICE_NAMES: dict[str, tuple[str, ...]] = {
    "api-gateway-cost-review": ("Amazon API Gateway",),
    "ecs-cost-governance-review": (
        "Amazon Elastic Container Service",
        "Amazon Elastic Container Service for EC2",
        "AWS Fargate",
    ),
    "eks-cost-risk-review": (
        "Amazon Elastic Kubernetes Service",
        "Amazon Elastic Container Service for Kubernetes",
    ),
    "opensearch-cost-review": ("Amazon OpenSearch Service",),
    "redshift-cost-review": ("Amazon Redshift",),
    "elasticache-cost-review": ("Amazon ElastiCache",),
}

TManagedPlatformRecord = TypeVar(
    "TManagedPlatformRecord",
    ApiGatewayRegionRecord,
    EcsRegionRecord,
    EksRegionRecord,
    OpenSearchRegionRecord,
    RedshiftRegionRecord,
    ElastiCacheRegionRecord,
)

ManagedPlatformRecord = ApiGatewayRegionRecord | EcsRegionRecord | EksRegionRecord | OpenSearchRegionRecord | RedshiftRegionRecord | ElastiCacheRegionRecord
