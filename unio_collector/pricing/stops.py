from __future__ import annotations  # noqa: D100

from unio_collector.pricing.enrich.constants import EXPECTED_PRICING_STOP_REASONS


class PricingLookupStoppedError(RuntimeError):  # noqa: D101
    def __init__(self, message: str, *, status: str) -> None:  # noqa: D107
        super().__init__(message)
        self.status = status


PricingLookupStopped = PricingLookupStoppedError


def is_expected_pricing_stop(reason: str) -> bool:  # noqa: D103
    return reason in EXPECTED_PRICING_STOP_REASONS
