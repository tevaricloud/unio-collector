"""Secret-safe origin header comparison contracts."""

from unio_collector.scanners.network.cloudfront_alb_protection.header.record import (
    HeaderMatchState,
    OriginHeaderVerificationRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.header.verifier import (
    OriginHeaderVerifier,
)

__all__ = ["HeaderMatchState", "OriginHeaderVerificationRecord", "OriginHeaderVerifier"]
