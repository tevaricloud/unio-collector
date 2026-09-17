from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudFrontVpcOriginRecord:
    """Sanitized CloudFront VPC-origin endpoint evidence."""

    vpc_origin_id: str
    endpoint_arn: str = ""
    http_port: int | None = None
    https_port: int | None = None
    origin_protocol_policy: str = ""
    status: str = ""
    evidence_ref: str = ""
    limitation: str = ""
