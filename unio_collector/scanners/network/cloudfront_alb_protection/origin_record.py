from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudFrontAlbOriginRecord:
    """CloudFront origin evidence needed to review ALB origin protection."""

    distribution_id: str
    distribution_arn: str
    distribution_domain_name: str
    origin_id: str
    origin_domain_name: str
    enabled: bool
    web_acl_id: str = ""
    origin_custom_header_names: tuple[str, ...] = ()
    source_restriction: str = ""
    evidence_ref: str = ""
    origin_kind: str = "custom"
    vpc_origin_id: str = ""
    http_port: int | None = None
    https_port: int | None = None
    origin_protocol_policy: str = ""
    host_forwarding_state: str = "unknown"
