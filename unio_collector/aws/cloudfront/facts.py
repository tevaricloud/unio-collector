"""Bounded joint counts of six provider cache-behavior observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

FLAG_COUNT = 6
BUCKET_COUNT = 1 << FLAG_COUNT
MAX_OBSERVATIONS = (1 << 63) - 1


@dataclass(frozen=True)
class CloudFrontBehaviorHistogram:
    """Count query, cookie, header, zero-TTL, policy-ID and legacy-map flags.

    Flag positions follow that order. Counts retain their intersections without
    retaining provider strings or individual behaviors. The fixed bucket count
    and integer bound cap serialized evidence independently of inventory size.
    """

    counts: tuple[int, ...]

    def __post_init__(self) -> None:
        """Reject incomplete, negative, boolean or oversized counters."""
        if len(self.counts) != BUCKET_COUNT or any(type(count) is not int or not 0 <= count <= MAX_OBSERVATIONS for count in self.counts):
            msg = "CloudFront behavior histogram requires 64 bounded integer counts."
            raise ValueError(msg)
        if sum(self.counts) > MAX_OBSERVATIONS:
            msg = "CloudFront behavior histogram exceeds its observation bound."
            raise ValueError(msg)
        object.__setattr__(self, "counts", tuple(self.counts))

    @classmethod
    def from_flags(cls, observations: Iterable[tuple[bool, ...]]) -> CloudFrontBehaviorHistogram:
        """Accumulate complete flag tuples with constant retained space."""
        counts = [0] * BUCKET_COUNT
        for flags in observations:
            if len(flags) != FLAG_COUNT or any(type(flag) is not bool for flag in flags):
                msg = "CloudFront behavior observation requires six boolean flags."
                raise ValueError(msg)
            counts[sum(1 << position for position, flag in enumerate(flags) if flag)] += 1
        return cls(tuple(counts))

    def count_flag(self, position: int) -> int:
        """Return the marginal count for one provider observation."""
        if type(position) is not int or not 0 <= position < FLAG_COUNT:
            msg = "CloudFront behavior flag position is unsupported."
            raise ValueError(msg)
        return sum(count for mask, count in enumerate(self.counts) if mask & (1 << position))
