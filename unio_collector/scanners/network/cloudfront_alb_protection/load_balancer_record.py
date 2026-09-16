from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AlbOriginLoadBalancerRecord:
    """ALB identity and access evidence for a CloudFront origin match."""

    arn: str
    name: str
    dns_name: str
    region: str
    scheme: str
    load_balancer_type: str
    security_group_ids: tuple[str, ...] = ()
    evidence_ref: str = ""
