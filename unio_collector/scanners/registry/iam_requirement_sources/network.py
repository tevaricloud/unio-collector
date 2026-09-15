from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.registry.iam_requirement_sources.network_cost.cloudfront.alb_origin import (
    CLOUDFRONT_ALB_ORIGIN_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.cloudfront.origin import (
    CLOUDFRONT_ORIGIN_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.cur_data_export import (
    CUR_DATA_EXPORT_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.data_transfer import (
    DATA_TRANSFER_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.nat_gateway import (
    NAT_GATEWAY_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.privatelink import (
    PRIVATELINK_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.public_ipv4 import (
    PUBLIC_IPV4_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.transit_gateway import (
    TRANSIT_GATEWAY_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.vpc.endpoint import (
    VPC_ENDPOINT_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.network_cost.vpc.flow_log import (
    VPC_FLOW_LOG_IAM_METADATA,
)

if TYPE_CHECKING:
    from unio_collector.scanners.registry.iam_requirements import (
        ScannerIamMetadataDeclaration,
    )

NETWORK_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    **CLOUDFRONT_ALB_ORIGIN_IAM_METADATA,
    **CLOUDFRONT_ORIGIN_IAM_METADATA,
    **CUR_DATA_EXPORT_IAM_METADATA,
    **DATA_TRANSFER_IAM_METADATA,
    **NAT_GATEWAY_IAM_METADATA,
    **PRIVATELINK_IAM_METADATA,
    **PUBLIC_IPV4_IAM_METADATA,
    **TRANSIT_GATEWAY_IAM_METADATA,
    **VPC_ENDPOINT_IAM_METADATA,
    **VPC_FLOW_LOG_IAM_METADATA,
}
