from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitRule:  # noqa: D101
    requests_per_second: float
    burst: int
    penalty_seconds: float = 1.0

    def validate(self, *, key: str) -> None:  # noqa: D102
        if self.requests_per_second <= 0:
            msg = f"Runtime rate limit {key}.requests_per_second must be positive."
            raise ValueError(
                msg,
            )
        if self.burst <= 0:
            msg = f"Runtime rate limit {key}.burst must be positive."
            raise ValueError(msg)
        if self.penalty_seconds < 0:
            msg = f"Runtime rate limit {key}.penalty_seconds cannot be negative."
            raise ValueError(
                msg,
            )

    def convert_to_dict(self) -> dict[str, float | int]:  # noqa: D102
        return {
            "requests_per_second": self.requests_per_second,
            "burst": self.burst,
            "penalty_seconds": self.penalty_seconds,
        }
