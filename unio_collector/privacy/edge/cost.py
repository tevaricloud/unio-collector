"""Explicit identity and fields for cloudfront-origin-cost-review."""

from typing import ClassVar

from unio_collector.privacy.edge.contract import EdgePrivacyContract
from unio_collector.privacy.edge.fields import COST


class CloudFrontCostPrivacyContract(EdgePrivacyContract):
    """Bind treatments only to the registered AWS collector evidence identity."""

    scanner_id: ClassVar[str] = "cloudfront-origin-cost-review"
    identities: ClassVar = {scanner_id: ("network.cloudfront_origin.evidence", "CloudFrontOriginCostReviewEvidence", {})}
    fields: ClassVar = COST
