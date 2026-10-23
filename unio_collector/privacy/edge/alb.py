"""Explicit identity and fields for cloudfront-alb-origin-protection-review."""

from typing import ClassVar

from unio_collector.privacy.edge.contract import EdgePrivacyContract
from unio_collector.privacy.edge.fields import ALB


class AlbOriginPrivacyContract(EdgePrivacyContract):
    """Bind treatments only to the registered AWS collector evidence identity."""

    scanner_id: ClassVar[str] = "cloudfront-alb-origin-protection-review"
    identities: ClassVar = {scanner_id: ("network.cloudfront_alb_protection.evidence", "CloudFrontAlbOriginProtectionEvidence", {})}
    fields: ClassVar = ALB
