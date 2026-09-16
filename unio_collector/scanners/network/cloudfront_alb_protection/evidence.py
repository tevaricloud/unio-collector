from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.scanners.network.cloudfront_alb_protection.coverage_record import (  # noqa: TC001
    OriginProtectionCoverageRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.header.record import (  # noqa: TC001
    OriginHeaderVerificationRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.listener.record import (  # noqa: TC001
    AlbOriginListenerRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.listener.rule_record import (  # noqa: TC001
    AlbOriginListenerRuleRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.load_balancer_record import (  # noqa: TC001
    AlbOriginLoadBalancerRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.origin_record import (  # noqa: TC001
    CloudFrontAlbOriginRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.security_group.record import (  # noqa: TC001
    AlbOriginSecurityGroupRuleRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.vpc_origin_record import (  # noqa: TC001
    CloudFrontVpcOriginRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.waf_record import (  # noqa: TC001
    AlbOriginWafAssociationRecord,
)


@dataclass(frozen=True)
class CloudFrontAlbOriginProtectionEvidence:
    """Serialized evidence for the CloudFront ALB origin protection review."""

    account_id: str = ""
    regions: list[str] = field(default_factory=list)
    collection_time: str = ""
    cloudfront_origins: tuple[CloudFrontAlbOriginRecord, ...] = ()
    load_balancers: tuple[AlbOriginLoadBalancerRecord, ...] = ()
    listeners: tuple[AlbOriginListenerRecord, ...] = ()
    listener_rules: tuple[AlbOriginListenerRuleRecord, ...] = ()
    vpc_origins: tuple[CloudFrontVpcOriginRecord, ...] = ()
    header_verifications: tuple[OriginHeaderVerificationRecord, ...] = ()
    coverage: tuple[OriginProtectionCoverageRecord, ...] = ()
    security_group_ids_collected: tuple[str, ...] = ()
    security_group_rules: tuple[AlbOriginSecurityGroupRuleRecord, ...] = ()
    waf_associations: tuple[AlbOriginWafAssociationRecord, ...] = ()
    limitations: tuple[str, ...] = field(default_factory=tuple)
