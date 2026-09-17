from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AlbOriginWafAssociationRecord:
    """WAF association evidence for CloudFront distributions or ALBs."""

    resource_id: str
    resource_type: str
    region: str
    associated: bool
    web_acl_id: str = ""
    evidence_ref: str = ""
    limitation: str = ""
