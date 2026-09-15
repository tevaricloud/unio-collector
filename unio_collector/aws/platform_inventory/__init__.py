from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.aws.api_gateway.region_record import ApiGatewayRegionRecord
from unio_collector.aws.ecs.region_record import EcsRegionRecord
from unio_collector.aws.eks.region_record import EksRegionRecord
from unio_collector.aws.elasticache.region_record import ElastiCacheRegionRecord
from unio_collector.aws.inventory_helpers import (
    AwsInventoryValueHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.opensearch.region_record import OpenSearchRegionRecord
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.platform_inventory.api_gateway.collector import (
    ManagedPlatformApiGatewayMixin,
)
from unio_collector.aws.platform_inventory.api_gateway.helpers import (
    ManagedPlatformApiGatewayHelpersMixin,
)
from unio_collector.aws.platform_inventory.common import (
    ManagedPlatformInventoryCommonMixin,
)
from unio_collector.aws.platform_inventory.ecs.api import (
    ManagedPlatformEcsApiMixin,
)
from unio_collector.aws.platform_inventory.ecs.collection import (
    ManagedPlatformEcsCollectionMixin,
)
from unio_collector.aws.platform_inventory.ecs.helpers import (
    ManagedPlatformEcsHelpersMixin,
)
from unio_collector.aws.platform_inventory.eks.collector import (
    ManagedPlatformEksMixin,
)
from unio_collector.aws.platform_inventory.eks.helpers import (
    ManagedPlatformEksHelpersMixin,
)
from unio_collector.aws.platform_inventory.elasticache import (
    ManagedPlatformElastiCacheMixin,
)
from unio_collector.aws.platform_inventory.entrypoint import (
    ManagedPlatformInventoryEntrypointMixin,
)
from unio_collector.aws.platform_inventory.search_redshift import (
    ManagedPlatformSearchRedshiftMixin,
)
from unio_collector.aws.redshift.region_record import RedshiftRegionRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext

__all__ = [
    "ApiGatewayRegionRecord",
    "EcsRegionRecord",
    "EksRegionRecord",
    "ElastiCacheRegionRecord",
    "ManagedPlatformInventoryCollector",
    "OpenSearchRegionRecord",
    "RedshiftRegionRecord",
    "normalize_api_gateway_vpc_link_detail_mode",
    "normalize_ecs_regional_collection_mode",
    "normalize_ecs_task_definition_detail_mode",
    "normalize_elasticache_metric_detail_mode",
]


class ManagedPlatformInventoryCollector(
    ManagedPlatformInventoryEntrypointMixin,
    ManagedPlatformApiGatewayMixin,
    ManagedPlatformApiGatewayHelpersMixin,
    ManagedPlatformEksMixin,
    ManagedPlatformEksHelpersMixin,
    ManagedPlatformEcsCollectionMixin,
    ManagedPlatformEcsApiMixin,
    ManagedPlatformEcsHelpersMixin,
    ManagedPlatformElastiCacheMixin,
    ManagedPlatformSearchRedshiftMixin,
    ManagedPlatformInventoryCommonMixin,
):
    """Collect read-only managed-platform metadata for cost review scanners."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        api_gateway_vpc_link_detail_mode: object = "full",
        ecs_task_definition_detail_mode: object = "full",
        ecs_regional_collection_mode: object = "full",
        elasticache_metric_detail_mode: object = "full",
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.api_gateway_vpc_link_detail_mode = normalize_api_gateway_vpc_link_detail_mode(api_gateway_vpc_link_detail_mode)
        self.ecs_task_definition_detail_mode = normalize_ecs_task_definition_detail_mode(ecs_task_definition_detail_mode)
        self.ecs_regional_collection_mode = normalize_ecs_regional_collection_mode(
            ecs_regional_collection_mode,
        )
        self.elasticache_metric_detail_mode = normalize_elasticache_metric_detail_mode(
            elasticache_metric_detail_mode,
        )
        self._pagination = AwsPaginationHelper()
        self._values = AwsInventoryValueHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="ManagedPlatformInventoryCollector",
        )
        self._available_regions_cache: list[str] | None = None


def normalize_api_gateway_vpc_link_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in {"full", "summary"}:
        return normalized
    msg = "API Gateway vpc_link_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(
        msg,
    )


def normalize_ecs_task_definition_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in {"full", "summary"}:
        return normalized
    msg = "ECS task_definition_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(
        msg,
    )


def normalize_ecs_regional_collection_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in {"full", "billing-active"}:
        return normalized
    msg = "ECS regional_collection_mode must be one of 'full' or 'billing-active'."
    raise ValueError(
        msg,
    )


def normalize_elasticache_metric_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in {"full", "summary"}:
        return normalized
    msg = "ElastiCache metric_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(
        msg,
    )
