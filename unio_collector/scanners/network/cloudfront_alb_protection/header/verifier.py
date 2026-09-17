from __future__ import annotations  # noqa: D100

import hmac
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.network.cloudfront_alb_protection.header.record import (
        HeaderMatchState,
    )


class OriginHeaderVerifier:
    """Compare transient CloudFront and ALB header values without persisting them."""

    def compare(
        self,
        cloudfront_headers: dict[str, str],
        alb_headers: dict[str, tuple[str, ...]],
    ) -> tuple[tuple[str, HeaderMatchState], ...]:
        """Return normalized header names and derived match states only."""
        normalized_cloudfront = {name.casefold(): value for name, value in cloudfront_headers.items()}
        results: list[tuple[str, HeaderMatchState]] = []
        for raw_name, values in sorted(alb_headers.items(), key=lambda item: item[0].casefold()):
            name = raw_name.casefold()
            if name not in normalized_cloudfront:
                results.append((name, "control_present"))
                continue
            expected = normalized_cloudfront[name]
            matched = any(hmac.compare_digest(expected, candidate) for candidate in values)
            results.append((name, "matched" if matched else "not_matched"))
        return tuple(results)
